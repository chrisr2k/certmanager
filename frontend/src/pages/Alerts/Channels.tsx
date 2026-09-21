import React, { useState } from 'react';
import {
  Card, Table, Tag, Button, Space, Typography, Modal, Form,
  Input, Select, InputNumber, message, Tooltip,
} from 'antd';
import {
  PlusOutlined, MailOutlined, SlackOutlined, WindowsOutlined,
  ApiOutlined, CheckCircleOutlined, CloseCircleOutlined,
  EditOutlined, DeleteOutlined, SendOutlined,
} from '@ant-design/icons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import apiClient from '../../api/client';

const { Title, Text } = Typography;

export default function ChannelsPage() {
  const queryClient = useQueryClient();
  const [form] = Form.useForm();
  const [modalOpen, setModalOpen] = useState(false);

  const { data, isLoading } = useQuery({
    queryKey: ['notification-channels'],
    queryFn: async () => {
      const { data } = await apiClient.get('/alerts/channels');
      return data.data || [];
    },
  });

  const createMutation = useMutation({
    mutationFn: async (values: any) => {
      await apiClient.post('/alerts/channels', values);
    },
    onSuccess: () => {
      message.success('Channel created');
      queryClient.invalidateQueries({ queryKey: ['notification-channels'] });
      setModalOpen(false);
      form.resetFields();
    },
    onError: (err: any) => message.error(err.response?.data?.message || 'Failed'),
  });

  const testMutation = useMutation({
    mutationFn: async (channelId: string) => {
      return await apiClient.post(`/alerts/channels/${channelId}/test`);
    },
    onSuccess: () => message.success('Test notification sent'),
    onError: () => message.error('Test failed'),
  });

  const handleSubmit = (values: any) => {
    const config: Record<string, any> = {};
    switch (values.channel_type) {
      case 'email':
        config.to = values.to;
        for (const k of ['smtp_host', 'smtp_port', 'smtp_user', 'smtp_password', 'from_address']) {
          if (values[k] !== undefined && values[k] !== null && values[k] !== '') config[k] = values[k];
        }
        break;
      case 'slack':
        config.webhook_url = values.webhook_url;
        if (values.channel) config.channel = values.channel;
        break;
      case 'teams':
        config.webhook_url = values.webhook_url;
        break;
      case 'webhook':
        config.url = values.url;
        config.method = values.method || 'POST';
        const headers: Record<string, string> = {};
        (values.headers || []).forEach((h: any) => {
          if (h?.key && h?.value !== undefined && h?.value !== '') headers[h.key] = h.value;
        });
        if (Object.keys(headers).length > 0) config.headers = headers;
        break;
    }
    createMutation.mutate({
      name: values.name,
      channel_type: values.channel_type,
      config,
    });
  };

  const channelIcons: Record<string, React.ReactNode> = {
    email: <MailOutlined />,
    slack: <SlackOutlined />,
    teams: <WindowsOutlined />,
    webhook: <ApiOutlined />,
  };

  const columns = [
    {
      title: 'Channel',
      dataIndex: 'name',
      key: 'name',
      render: (name: string, record: any) => (
        <Space>
          {channelIcons[record.channel_type] || <ApiOutlined />}
          <span>{name}</span>
        </Space>
      ),
    },
    {
      title: 'Type',
      dataIndex: 'channel_type',
      key: 'type',
      width: 100,
      render: (t: string) => <Tag>{t}</Tag>,
    },
    {
      title: 'Verified',
      dataIndex: 'is_verified',
      key: 'verified',
      width: 90,
      render: (v: boolean) => (
        <Tag color={v ? 'green' : 'default'} icon={v ? <CheckCircleOutlined /> : <CloseCircleOutlined />}>
          {v ? 'Yes' : 'No'}
        </Tag>
      ),
    },
    {
      title: 'Actions',
      key: 'actions',
      width: 120,
      render: (_: any, record: any) => (
        <Space>
          <Tooltip title="Test"><Button type="link" size="small" icon={<SendOutlined />} onClick={() => testMutation.mutate(record.id)} /></Tooltip>
        </Space>
      ),
    },
  ];

  const channels = data || [];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <Title level={3} style={{ margin: 0 }}>Notification Channels</Title>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => { form.resetFields(); setModalOpen(true); }}>
          Add Channel
        </Button>
      </div>

      <Card>
        {channels.length === 0 ? (
          <div style={{ textAlign: 'center', padding: 40, color: '#8c8c8c' }}>
            <ApiOutlined style={{ fontSize: 48 }} />
            <div style={{ marginTop: 12, fontSize: 16 }}>No notification channels</div>
            <Button type="primary" style={{ marginTop: 12 }} onClick={() => setModalOpen(true)}>
              Add your first channel
            </Button>
          </div>
        ) : (
          <Table dataSource={channels} columns={columns} rowKey="id" loading={isLoading} pagination={false} />
        )}
      </Card>

      <Modal
        title="Add Notification Channel"
        open={modalOpen}
        onCancel={() => setModalOpen(false)}
        onOk={() => form.submit()}
        confirmLoading={createMutation.isPending}
        width={560}
      >
        <Form form={form} layout="vertical" onFinish={handleSubmit}>
          <Form.Item name="name" label="Channel Name" rules={[{ required: true }]}>
            <Input placeholder="e.g., Ops Team Email" />
          </Form.Item>

          <Form.Item name="channel_type" label="Channel Type" rules={[{ required: true }]}>
            <Select
              options={[
                { value: 'email', label: 'Email (SMTP)' },
                { value: 'slack', label: 'Slack Webhook' },
                { value: 'teams', label: 'Microsoft Teams' },
                { value: 'webhook', label: 'Generic Webhook' },
              ]}
            />
          </Form.Item>

          <Form.Item noStyle shouldUpdate={(prev, cur) => prev.channel_type !== cur.channel_type}>
            {({ getFieldValue }) => {
              const type = getFieldValue('channel_type');
              if (type === 'email') {
                return (
                  <>
                    <Form.Item name="to" label="Recipients"
                      rules={[{ required: true, message: 'At least one recipient is required' }]}>
                      <Select mode="tags" placeholder="Type an email and press Enter" open={false} suffixIcon={null} />
                    </Form.Item>
                    <Text type="secondary" style={{ fontSize: 12 }}>
                      SMTP settings are optional — leave blank to use the server defaults.
                    </Text>
                    <Form.Item name="smtp_host" label="SMTP Host">
                      <Input placeholder="server default" />
                    </Form.Item>
                    <Form.Item name="smtp_port" label="SMTP Port">
                      <InputNumber style={{ width: '100%' }} placeholder="server default" />
                    </Form.Item>
                    <Form.Item name="smtp_user" label="SMTP User">
                      <Input placeholder="server default" />
                    </Form.Item>
                    <Form.Item name="smtp_password" label="SMTP Password">
                      <Input.Password placeholder="server default" />
                    </Form.Item>
                    <Form.Item name="from_address" label="From Address">
                      <Input placeholder="server default" />
                    </Form.Item>
                  </>
                );
              }
              if (type === 'slack') {
                return (
                  <>
                    <Form.Item name="webhook_url" label="Webhook URL"
                      rules={[{ required: true, message: 'Webhook URL is required' }]}>
                      <Input placeholder="https://hooks.slack.com/services/..." />
                    </Form.Item>
                    <Form.Item name="channel" label="Channel (optional)">
                      <Input placeholder="#cert-alerts — overrides the webhook default" />
                    </Form.Item>
                  </>
                );
              }
              if (type === 'teams') {
                return (
                  <Form.Item name="webhook_url" label="Webhook URL"
                    rules={[{ required: true, message: 'Webhook URL is required' }]}>
                    <Input placeholder="https://outlook.office.com/webhook/..." />
                  </Form.Item>
                );
              }
              if (type === 'webhook') {
                return (
                  <>
                    <Form.Item name="url" label="URL"
                      rules={[{ required: true, message: 'URL is required' }]}>
                      <Input placeholder="https://api.example.com/alerts" />
                    </Form.Item>
                    <Form.Item name="method" label="Method" initialValue="POST">
                      <Select options={['POST', 'PUT', 'GET'].map((m) => ({ value: m, label: m }))} />
                    </Form.Item>
                    <Form.Item label="Headers (optional)">
                      <Form.List name="headers" initialValue={[{}]}>
                        {(fields, { add, remove }) => (
                          <>
                            {fields.map((field) => (
                              <Space key={field.key} align="baseline" style={{ display: 'flex', marginBottom: 8 }}>
                                <Form.Item name={[field.name, 'key']} style={{ marginBottom: 0 }}>
                                  <Input placeholder="Header (e.g. Authorization)" style={{ width: 200 }} />
                                </Form.Item>
                                <Form.Item name={[field.name, 'value']} style={{ marginBottom: 0 }}>
                                  <Input placeholder="Value" style={{ width: 200 }} />
                                </Form.Item>
                                <Button type="link" size="small" onClick={() => remove(field.name)}>✕</Button>
                              </Space>
                            ))}
                            <Button type="dashed" size="small" onClick={() => add()} block>
                              + Add header
                            </Button>
                          </>
                        )}
                      </Form.List>
                    </Form.Item>
                  </>
                );
              }
              return null;
            }}
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
