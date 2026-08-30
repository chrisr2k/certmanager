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
    createMutation.mutate({
      name: values.name,
      channel_type: values.channel_type,
      config: values.config ? JSON.parse(values.config) : {},
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
              let configPlaceholder = '{}';
              if (type === 'email') {
                configPlaceholder = '{"to": ["ops@example.com"], "smtp_host": "smtp.example.com", "smtp_port": 587}';
              } else if (type === 'slack' || type === 'teams') {
                configPlaceholder = '{"webhook_url": "https://hooks.example.com/..."}';
              } else if (type === 'webhook') {
                configPlaceholder = '{"url": "https://api.example.com/alerts", "method": "POST", "headers": {"Authorization": "Bearer ..."}}';
              }
              return (
                <Form.Item
                  name="config"
                  label="Configuration (JSON)"
                  rules={[
                    { required: true, message: 'Configuration is required' },
                    { validator: (_, value) => {
                      if (!value) return Promise.resolve();
                      try { JSON.parse(value); return Promise.resolve(); }
                      catch { return Promise.reject('Invalid JSON'); }
                    }},
                  ]}
                  initialValue={configPlaceholder}
                >
                  <Input.TextArea rows={6} placeholder={configPlaceholder} style={{ fontFamily: 'monospace', fontSize: 12 }} />
                </Form.Item>
              );
            }}
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
