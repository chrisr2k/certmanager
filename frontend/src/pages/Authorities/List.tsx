import React, { useState } from 'react';
import { Card, Table, Tag, Button, Space, Typography, Modal, Form, Input, Select, message } from 'antd';
import { PlusOutlined, ReloadOutlined, SafetyCertificateOutlined, SyncOutlined, DownloadOutlined } from '@ant-design/icons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import apiClient, { getEnveloped } from '../../api/client';
import AddAuthorityModal from '../../components/AddAuthorityModal';
import { saveTextFile } from '../../utils/download';

const { Title, Text } = Typography;

// Polls a scan job until it reaches a terminal state, surfacing a
// "Download Key" action once an issue/renew job's key bundle is ready.
// Shared by ACME (always produces a bundle) and AD CS (only produces one
// when deliver_key_to_central is enabled on the CA).
function IssuanceJobStatus({ jobId, onDone }: { jobId: string; onDone: () => void }) {
  const { data: job } = useQuery({
    queryKey: ['scan-job', jobId],
    queryFn: () => getEnveloped(`/scans/${jobId}`),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === 'completed' || status === 'failed' ? false : 3000;
    },
  });

  const downloadMutation = useMutation({
    mutationFn: async (downloadUrl: string) => {
      // Must go through apiClient (not a raw <a href>) so the request
      // carries the Authorization header — this endpoint requires it.
      const { data } = await apiClient.get(downloadUrl.replace(/^\/api\/v1/, ''));
      return data.data as {
        private_key_pem: string;
        certificate_pem: string;
        chain_pem: string;
        fullchain_pem: string;
      };
    },
    onSuccess: (bundle, downloadUrl) => {
      const bundleId = downloadUrl.split('/').slice(-2, -1)[0];
      saveTextFile(`certmanager-${bundleId.slice(0, 8)}.key.pem`, bundle.private_key_pem);
      saveTextFile(`certmanager-${bundleId.slice(0, 8)}.fullchain.pem`, bundle.fullchain_pem);
      message.success('Private key and fullchain downloaded');
      onDone();
    },
    onError: () => message.error('Download failed — the key bundle may have expired (48h TTL)'),
  });

  if (!job) return <Text type="secondary">Checking status…</Text>;

  if (job.status === 'failed') {
    return <Text type="danger">Failed: {job.error_detail?.[0] || 'unknown error'}</Text>;
  }
  if (job.status === 'completed' && job.download_url) {
    return (
      <Space>
        <Tag color="green">Ready</Tag>
        <Button
          size="small"
          type="primary"
          icon={<DownloadOutlined />}
          loading={downloadMutation.isPending}
          onClick={() => downloadMutation.mutate(job.download_url)}
        >
          Download Key
        </Button>
      </Space>
    );
  }
  if (job.status === 'completed') {
    // AD CS without deliver_key_to_central — the key stayed on the agent
    // and was never sent here, so there's nothing to download.
    return <Tag color="green">Completed — key stayed on the agent</Tag>;
  }
  return <Tag color="blue">{job.status}…</Tag>;
}

export default function AuthoritiesList() {
  const queryClient = useQueryClient();
  const [addOpen, setAddOpen] = useState(false);
  const [issueTarget, setIssueTarget] = useState<any>(null);
  const [renewTarget, setRenewTarget] = useState<any>(null);
  const [activeJob, setActiveJob] = useState<{ authorityId: string; jobId: string } | null>(null);
  const [issueForm] = Form.useForm();
  const [renewForm] = Form.useForm();

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['authorities'],
    queryFn: async () => {
      const { data } = await apiClient.get('/authorities');
      return data.data || [];
    },
  });

  const issueMutation = useMutation({
    mutationFn: ({ authorityId, values }: { authorityId: string; values: any }) =>
      apiClient.post(`/authorities/${authorityId}/issue`, values),
    onSuccess: (resp: any, { authorityId }) => {
      message.success('Certificate issuance dispatched');
      setActiveJob({ authorityId, jobId: resp.data.data.scan_job_id });
      setIssueTarget(null);
      issueForm.resetFields();
    },
  });

  const renewMutation = useMutation({
    mutationFn: ({ authorityId, values }: { authorityId: string; values: any }) =>
      apiClient.post(`/authorities/${authorityId}/renew`, values),
    onSuccess: (resp: any, { authorityId }) => {
      message.success('Certificate renewal dispatched');
      setActiveJob({ authorityId, jobId: resp.data.data.scan_job_id });
      setRenewTarget(null);
      renewForm.resetFields();
    },
  });

  const columns = [
    { title: 'Name', dataIndex: 'name', key: 'name' },
    {
      title: 'Type',
      dataIndex: 'ca_type',
      key: 'type',
      render: (t: string) => t.replace('_', ' ').toUpperCase(),
    },
    {
      title: 'Health',
      dataIndex: 'health_status',
      key: 'health',
      render: (h: string) => (
        <Tag
          color={
            h === 'healthy' ? 'green' : h === 'degraded' ? 'orange' : h === 'unhealthy' ? 'red' : 'default'
          }
        >
          {h}
        </Tag>
      ),
    },
    {
      title: 'Last Scan',
      dataIndex: 'last_scan_at',
      key: 'last_scan',
      render: (d: string) => (d ? new Date(d).toLocaleString() : 'Never'),
    },
    {
      title: 'Active',
      dataIndex: 'is_active',
      key: 'active',
      render: (a: boolean) => <Tag color={a ? 'green' : 'default'}>{a ? 'Yes' : 'No'}</Tag>,
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_: any, record: any) =>
        record.ca_type === 'acme' || record.ca_type === 'adcs' ? (
          <Space size="small">
            <Button size="small" icon={<SafetyCertificateOutlined />} onClick={() => setIssueTarget(record)}>
              Issue
            </Button>
            <Button size="small" icon={<SyncOutlined />} onClick={() => setRenewTarget(record)}>
              Renew
            </Button>
          </Space>
        ) : null,
    },
  ];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <Title level={3} style={{ margin: 0 }}>Certificate Authorities</Title>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={() => refetch()}>Refresh</Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setAddOpen(true)}>Add Authority</Button>
        </Space>
      </div>

      {activeJob && (
        <Card size="small" style={{ marginBottom: 16 }} title="Certificate job in progress">
          <IssuanceJobStatus
            jobId={activeJob.jobId}
            onDone={() => queryClient.invalidateQueries({ queryKey: ['certificates'] })}
          />
        </Card>
      )}

      <Card>
        <Table
          dataSource={data}
          columns={columns}
          rowKey="id"
          loading={isLoading}
          pagination={false}
        />
      </Card>

      <AddAuthorityModal open={addOpen} onClose={() => setAddOpen(false)} />

      <Modal
        title={`Issue Certificate — ${issueTarget?.name || ''}`}
        open={!!issueTarget}
        onOk={() => issueForm.submit()}
        confirmLoading={issueMutation.isPending}
        onCancel={() => setIssueTarget(null)}
        okText="Issue"
      >
        <Form
          form={issueForm}
          layout="vertical"
          onFinish={(values) => issueMutation.mutate({ authorityId: issueTarget.id, values })}
        >
          <Form.Item name="common_name" label="Common Name"
            rules={[{ required: true, message: 'Common name is required' }]}>
            <Input placeholder="www.example.com" autoFocus />
          </Form.Item>
          <Form.Item name="sans" label="Additional SANs (optional)">
            <Select mode="tags" placeholder="api.example.com (press Enter to add more)" open={false} suffixIcon={null} />
          </Form.Item>
          <Form.Item name="key_algorithm" label="Key Algorithm" initialValue="RSA-2048">
            <Select options={[
              { value: 'RSA-2048', label: 'RSA-2048' },
              { value: 'RSA-4096', label: 'RSA-4096' },
              { value: 'ECDSA-P256', label: 'ECDSA-P256' },
            ]} />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={`Renew Certificate — ${renewTarget?.name || ''}`}
        open={!!renewTarget}
        onOk={() => renewForm.submit()}
        confirmLoading={renewMutation.isPending}
        onCancel={() => setRenewTarget(null)}
        okText="Renew"
      >
        <Form
          form={renewForm}
          layout="vertical"
          onFinish={(values) => renewMutation.mutate({ authorityId: renewTarget.id, values })}
        >
          <Form.Item name="certificate_id" label="Certificate"
            tooltip="The inventory ID of the certificate to renew — find it on the Certificates page"
            rules={[{ required: true, message: 'Certificate ID is required' }]}>
            <Input placeholder="Certificate UUID from the Certificates page" autoFocus />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
