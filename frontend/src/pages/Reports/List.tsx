import React, { useState } from 'react';
import {
  Card, Table, Tag, Button, Space, Typography, Modal, Form,
  Select, InputNumber, DatePicker, message,
} from 'antd';
import {
  PlusOutlined, DownloadOutlined, FilePdfOutlined,
  FileTextOutlined, ReloadOutlined, FileExcelOutlined,
} from '@ant-design/icons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import apiClient from '../../api/client';

const { Title, Text } = Typography;

export default function ReportsList() {
  const queryClient = useQueryClient();
  const [form] = Form.useForm();
  const [modalOpen, setModalOpen] = useState(false);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['reports'],
    queryFn: async () => {
      const { data } = await apiClient.get('/reports');
      return data.data || [];
    },
  });

  const generateMutation = useMutation({
    mutationFn: async (values: any) => {
      await apiClient.post('/reports', {
        report_type: values.report_type,
        parameters: {
          days: values.days || 30,
          datacenter_ids: values.datacenter_ids || [],
          status: values.status || undefined,
        },
        file_format: values.file_format || 'pdf',
      });
    },
    onSuccess: () => {
      message.success('Report generation dispatched');
      queryClient.invalidateQueries({ queryKey: ['reports'] });
      setModalOpen(false);
      form.resetFields();
    },
    onError: (err: any) => message.error(err.response?.data?.message || 'Failed'),
  });

  const handleDownload = (report: any) => {
    const token = localStorage.getItem('access_token');
    const url = `${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/api/v1/reports/${report.id}/download`;
    // Open download in new tab with auth
    const a = document.createElement('a');
    a.href = url;
    a.download = `certmanager-${report.report_type}-${report.id.slice(0, 8)}.${report.file_format || 'pdf'}`;
    // We need to fetch with auth header since anchor can't set headers
    fetch(url, { headers: { Authorization: `Bearer ${token}` } })
      .then(res => res.blob())
      .then(blob => {
        const blobUrl = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = blobUrl;
        link.download = a.download;
        link.click();
        URL.revokeObjectURL(blobUrl);
      })
      .catch(() => message.error('Download failed'));
  };

  const columns = [
    {
      title: 'Type',
      dataIndex: 'report_type',
      key: 'type',
      width: 200,
      render: (t: string) => {
        const labels: Record<string, string> = {
          expiry_summary: 'Expiry Summary',
          full_inventory: 'Full Inventory',
          change_report: 'Change Report',
          audit_export: 'Audit Export',
        };
        return labels[t] || t.replace(/_/g, ' ');
      },
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 120,
      render: (s: string) => (
        <Tag
          color={
            s === 'completed' ? 'green'
            : s === 'generating' ? 'blue'
            : s === 'failed' ? 'red'
            : 'default'
          }
        >
          {s}
        </Tag>
      ),
    },
    {
      title: 'Format',
      dataIndex: 'file_format',
      key: 'format',
      width: 70,
      render: (f: string) => (
        f === 'pdf' ? <FilePdfOutlined style={{ color: '#ff4d4f' }} />
        : f === 'csv' ? <FileExcelOutlined style={{ color: '#52c41a' }} />
        : <FileTextOutlined />
      ),
    },
    {
      title: 'Generated',
      dataIndex: 'generated_at',
      key: 'generated',
      width: 180,
      render: (d: string | null) =>
        d ? new Date(d).toLocaleString() : <Text type="secondary">Pending</Text>,
    },
    {
      title: 'Action',
      key: 'action',
      width: 100,
      render: (_: any, record: any) =>
        record.status === 'completed' ? (
          <Button
            type="link"
            icon={<DownloadOutlined />}
            onClick={() => handleDownload(record)}
          >
            Download
          </Button>
        ) : null,
    },
  ];

  const reports = data || [];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <Title level={3} style={{ margin: 0 }}>Compliance Reports</Title>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={() => refetch()}>Refresh</Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => { form.resetFields(); setModalOpen(true); }}>
            Generate Report
          </Button>
        </Space>
      </div>

      <Card>
        {reports.length === 0 ? (
          <div style={{ textAlign: 'center', padding: 40, color: '#8c8c8c' }}>
            <FileTextOutlined style={{ fontSize: 48 }} />
            <div style={{ marginTop: 12, fontSize: 16 }}>No reports generated yet</div>
            <Button type="primary" style={{ marginTop: 12 }} onClick={() => setModalOpen(true)}>
              Generate your first report
            </Button>
          </div>
        ) : (
          <Table
            dataSource={reports}
            columns={columns}
            rowKey="id"
            loading={isLoading}
            pagination={{ pageSize: 25, showTotal: (t) => `${t} reports` }}
          />
        )}
      </Card>

      <Modal
        title="Generate Compliance Report"
        open={modalOpen}
        onCancel={() => setModalOpen(false)}
        onOk={() => form.submit()}
        confirmLoading={generateMutation.isPending}
        width={480}
      >
        <Form form={form} layout="vertical" onFinish={(v) => generateMutation.mutate(v)}>
          <Form.Item name="report_type" label="Report Type" rules={[{ required: true }]}
            initialValue="expiry_summary"
          >
            <Select options={[
              { value: 'expiry_summary', label: 'Expiry Summary — certs expiring within N days' },
              { value: 'full_inventory', label: 'Full Inventory — all certificates' },
              { value: 'change_report', label: 'Change Report — new/renewed/expired in period' },
              { value: 'audit_export', label: 'Audit Export — audit log entries' },
            ]} />
          </Form.Item>

          <Form.Item name="file_format" label="Output Format" initialValue="pdf">
            <Select options={[
              { value: 'pdf', label: 'PDF' },
              { value: 'csv', label: 'CSV' },
              { value: 'json', label: 'JSON' },
            ]} />
          </Form.Item>

          <Form.Item name="days" label="Period (days)" initialValue={30}>
            <InputNumber min={1} max={365} style={{ width: '100%' }} addonAfter="days" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
