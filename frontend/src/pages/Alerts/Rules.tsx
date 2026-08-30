import React, { useState } from 'react';
import {
  Card, Table, Tag, Switch, Button, Space, Typography, Modal, Form,
  Input, Select, InputNumber, message, Popconfirm, Tooltip,
} from 'antd';
import {
  PlusOutlined, EditOutlined, DeleteOutlined, BellOutlined,
  ThunderboltOutlined, SettingOutlined,
} from '@ant-design/icons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import apiClient from '../../api/client';

const { Title, Text } = Typography;

export default function AlertsRules() {
  const queryClient = useQueryClient();
  const [form] = Form.useForm();
  const [editRule, setEditRule] = useState<any>(null);
  const [modalOpen, setModalOpen] = useState(false);

  const { data, isLoading } = useQuery({
    queryKey: ['alert-rules'],
    queryFn: async () => {
      const { data } = await apiClient.get('/alerts/rules');
      return data.data || [];
    },
  });

  const createMutation = useMutation({
    mutationFn: async (values: any) => {
      await apiClient.post('/alerts/rules', values);
    },
    onSuccess: () => {
      message.success('Alert rule created');
      queryClient.invalidateQueries({ queryKey: ['alert-rules'] });
      setModalOpen(false);
      form.resetFields();
    },
    onError: (err: any) => message.error(err.response?.data?.message || 'Failed'),
  });

  const deleteMutation = useMutation({
    mutationFn: async (ruleId: string) => {
      await apiClient.delete(`/alerts/rules/${ruleId}`);
    },
    onSuccess: () => {
      message.success('Rule deleted');
      queryClient.invalidateQueries({ queryKey: ['alert-rules'] });
    },
  });

  const openCreate = () => {
    setEditRule(null);
    form.resetFields();
    form.setFieldsValue({
      severity: 'warning',
      condition_type: 'expiry_days',
      cooldown_minutes: 60,
    });
    setModalOpen(true);
  };

  const openEdit = (rule: any) => {
    setEditRule(rule);
    form.setFieldsValue({
      name: rule.name,
      description: rule.description,
      condition_type: rule.condition_type,
      severity: rule.severity,
      cooldown_minutes: rule.cooldown_minutes,
      days: rule.condition_config?.days || 30,
      issuer_pattern: rule.condition_config?.issuer_pattern || '',
      status: rule.condition_config?.status || 'expired',
      health_status: rule.condition_config?.health_status || 'unhealthy',
    });
    setModalOpen(true);
  };

  const handleSubmit = (values: any) => {
    // Build condition_config from form fields
    let condition_config = {};
    switch (values.condition_type) {
      case 'expiry_days':
        condition_config = { days: values.days || 30 };
        break;
      case 'issuer_match':
        condition_config = { issuer_pattern: values.issuer_pattern || '' };
        break;
      case 'status_change':
        condition_config = { status: values.status || 'expired', within_hours: 24 };
        break;
      case 'ca_health':
        condition_config = { health_status: values.health_status || 'unhealthy' };
        break;
    }

    createMutation.mutate({
      name: values.name,
      description: values.description,
      condition_type: values.condition_type,
      condition_config,
      severity: values.severity,
      cooldown_minutes: values.cooldown_minutes,
    });
  };

  const columns = [
    {
      title: 'Rule',
      dataIndex: 'name',
      key: 'name',
      render: (name: string, record: any) => (
        <Space>
          <BellOutlined style={{ color: record.severity === 'critical' ? '#ff4d4f' : record.severity === 'warning' ? '#faad14' : '#1677ff' }} />
          <a onClick={() => openEdit(record)}>{name}</a>
        </Space>
      ),
    },
    {
      title: 'Condition',
      dataIndex: 'condition_type',
      key: 'condition',
      width: 170,
      render: (t: string, record: any) => {
        const labels: Record<string, string> = {
          expiry_days: 'Expiry Warning',
          issuer_match: 'Issuer Match',
          status_change: 'Status Change',
          ca_health: 'CA Health',
          ct_new_cert: 'CT New Cert',
        };
        const config = record.condition_config || {};
        let detail = '';
        if (t === 'expiry_days') detail = `≤ ${config.days || 30}d`;
        else if (t === 'issuer_match') detail = config.issuer_pattern || '';
        else if (t === 'status_change') detail = config.status || 'expired';
        else if (t === 'ca_health') detail = config.health_status || 'unhealthy';

        return (
          <Space direction="vertical" size={0}>
            <Text>{labels[t] || t}</Text>
            {detail && <Text type="secondary" style={{ fontSize: 11 }}>{detail}</Text>}
          </Space>
        );
      },
    },
    {
      title: 'Severity',
      dataIndex: 'severity',
      key: 'severity',
      width: 100,
      render: (s: string) => (
        <Tag color={s === 'critical' ? 'red' : s === 'warning' ? 'orange' : 'blue'}>{s}</Tag>
      ),
    },
    {
      title: 'Cooldown',
      dataIndex: 'cooldown_minutes',
      key: 'cooldown',
      width: 90,
      render: (m: number) => `${m}m`,
    },
    {
      title: 'Enabled',
      dataIndex: 'is_enabled',
      key: 'enabled',
      width: 80,
      render: (e: boolean) => <Switch checked={e} disabled size="small" />,
    },
    {
      title: 'Actions',
      key: 'actions',
      width: 100,
      render: (_: any, record: any) => (
        <Space>
          <Tooltip title="Edit"><Button type="link" size="small" icon={<EditOutlined />} onClick={() => openEdit(record)} /></Tooltip>
          <Popconfirm title="Delete this rule?" onConfirm={() => deleteMutation.mutate(record.id)}>
            <Tooltip title="Delete"><Button type="link" danger size="small" icon={<DeleteOutlined />} /></Tooltip>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  const rules = data || [];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <Title level={3} style={{ margin: 0 }}>Alert Rules</Title>
        <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>Create Rule</Button>
      </div>

      <Card>
        {rules.length === 0 ? (
          <div style={{ textAlign: 'center', padding: 40, color: '#8c8c8c' }}>
            <BellOutlined style={{ fontSize: 48 }} />
            <div style={{ marginTop: 12, fontSize: 16 }}>No alert rules configured</div>
            <Button type="primary" style={{ marginTop: 12 }} onClick={openCreate}>
              Create your first alert rule
            </Button>
          </div>
        ) : (
          <Table dataSource={rules} columns={columns} rowKey="id" loading={isLoading} pagination={false} />
        )}
      </Card>

      {/* Create/Edit Modal */}
      <Modal
        title={editRule ? `Edit Rule: ${editRule.name}` : 'Create Alert Rule'}
        open={modalOpen}
        onCancel={() => { setModalOpen(false); form.resetFields(); }}
        onOk={() => form.submit()}
        confirmLoading={createMutation.isPending}
        width={560}
      >
        <Form form={form} layout="vertical" onFinish={handleSubmit}>
          <Form.Item name="name" label="Rule Name" rules={[{ required: true }]}>
            <Input placeholder="e.g., Critical certs expiring in 7 days" />
          </Form.Item>

          <Form.Item name="description" label="Description">
            <Input.TextArea rows={2} placeholder="What this rule detects..." />
          </Form.Item>

          <Form.Item name="condition_type" label="Condition Type" rules={[{ required: true }]}>
            <Select
              options={[
                { value: 'expiry_days', label: 'Expiry Warning — fire when certs expire within N days' },
                { value: 'issuer_match', label: 'Issuer Match — fire when issuer matches a pattern' },
                { value: 'status_change', label: 'Status Change — fire when cert status changes' },
                { value: 'ca_health', label: 'CA Health — fire when a CA becomes unhealthy' },
                { value: 'ct_new_cert', label: 'CT New Cert — fire on unknown CT log entries' },
              ]}
            />
          </Form.Item>

          <Form.Item noStyle shouldUpdate={(prev, cur) => prev.condition_type !== cur.condition_type}>
            {({ getFieldValue }) => {
              const condType = getFieldValue('condition_type');
              return (
                <>
                  {condType === 'expiry_days' && (
                    <Form.Item name="days" label="Expiry threshold (days)">
                      <InputNumber min={1} max={365} style={{ width: '100%' }} addonAfter="days" />
                    </Form.Item>
                  )}
                  {condType === 'issuer_match' && (
                    <Form.Item name="issuer_pattern" label="Issuer Pattern (regex or substring)" rules={[{ required: true }]}>
                      <Input placeholder="e.g., CN=Test CA.* or COMODO" />
                    </Form.Item>
                  )}
                  {condType === 'status_change' && (
                    <Form.Item name="status" label="Target Status">
                      <Select options={[
                        { value: 'expired', label: 'Expired' },
                        { value: 'revoked', label: 'Revoked' },
                      ]} />
                    </Form.Item>
                  )}
                  {condType === 'ca_health' && (
                    <Form.Item name="health_status" label="Health Status">
                      <Select options={[
                        { value: 'unhealthy', label: 'Unhealthy' },
                        { value: 'degraded', label: 'Degraded' },
                      ]} />
                    </Form.Item>
                  )}
                </>
              );
            }}
          </Form.Item>

          <Space style={{ width: '100%' }} size="middle">
            <Form.Item name="severity" label="Severity" style={{ flex: 1 }}>
              <Select options={[
                { value: 'info', label: 'Info' },
                { value: 'warning', label: 'Warning' },
                { value: 'critical', label: 'Critical' },
              ]} />
            </Form.Item>
            <Form.Item name="cooldown_minutes" label="Cooldown" style={{ flex: 1 }}>
              <InputNumber min={0} max={1440} style={{ width: '100%' }} addonAfter="minutes" />
            </Form.Item>
          </Space>
        </Form>
      </Modal>
    </div>
  );
}
