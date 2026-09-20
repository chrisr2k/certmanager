import React, { useState } from 'react';
import { Card, Table, Tag, Button, Space, Typography, Modal, Form, Input, Select, Switch, message } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import apiClient, { getEnveloped } from '../../api/client';

const { Title } = Typography;

export default function AdminUsers() {
  const queryClient = useQueryClient();
  const [addOpen, setAddOpen] = useState(false);
  const [addForm] = Form.useForm();

  const { data, isLoading } = useQuery({
    queryKey: ['users'],
    queryFn: async () => {
      const { data } = await apiClient.get('/users');
      return data.data || [];
    },
  });

  const { data: roles } = useQuery({
    queryKey: ['roles-list'],
    queryFn: () => getEnveloped('/users/roles'),
    enabled: addOpen,
  });

  const createMutation = useMutation({
    mutationFn: (values: any) => apiClient.post('/users', values),
    onSuccess: () => {
      message.success('User created');
      setAddOpen(false);
      addForm.resetFields();
      queryClient.invalidateQueries({ queryKey: ['users'] });
    },
  });

  const columns = [
    { title: 'Email', dataIndex: 'email', key: 'email' },
    { title: 'Name', dataIndex: 'full_name', key: 'name' },
    {
      title: 'Roles',
      dataIndex: 'roles',
      key: 'roles',
      render: (roles: string[]) => roles.map((r) => <Tag key={r}>{r}</Tag>),
    },
    {
      title: 'Superuser',
      dataIndex: 'is_superuser',
      key: 'superuser',
      render: (s: boolean) => <Tag color={s ? 'red' : 'default'}>{s ? 'Yes' : 'No'}</Tag>,
    },
    {
      title: 'MFA',
      dataIndex: 'mfa_enabled',
      key: 'mfa',
      render: (m: boolean) => <Tag color={m ? 'green' : 'default'}>{m ? 'Enabled' : 'Disabled'}</Tag>,
    },
    {
      title: 'Active',
      dataIndex: 'is_active',
      key: 'active',
      render: (a: boolean) => <Tag color={a ? 'green' : 'red'}>{a ? 'Yes' : 'No'}</Tag>,
    },
  ];

  const roleList = Array.isArray(roles) ? roles : roles?.data || roles?.roles || [];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <Title level={3} style={{ margin: 0 }}>Users</Title>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setAddOpen(true)}>Add User</Button>
      </div>
      <Card>
        <Table dataSource={data} columns={columns} rowKey="id" loading={isLoading} pagination={{ pageSize: 25 }} />
      </Card>

      <Modal
        title="Add User"
        open={addOpen}
        onOk={() => addForm.submit()}
        confirmLoading={createMutation.isPending}
        onCancel={() => setAddOpen(false)}
        okText="Create"
      >
        <Form
          form={addForm}
          layout="vertical"
          onFinish={(values) => createMutation.mutate({
            email: values.email,
            password: values.password,
            full_name: values.full_name || undefined,
            is_superuser: values.is_superuser || false,
            role_ids: values.role_ids || undefined,
          })}
        >
          <Form.Item
            name="email"
            label="Email"
            rules={[{ required: true, type: 'email', message: 'Valid email is required' }]}
          >
            <Input placeholder="user@example.com" autoFocus />
          </Form.Item>
          <Form.Item
            name="password"
            label="Password"
            rules={[
              { required: true, message: 'Password is required' },
              { min: 12, message: 'At least 12 characters' },
            ]}
          >
            <Input.Password placeholder="Minimum 12 characters" />
          </Form.Item>
          <Form.Item name="full_name" label="Full Name">
            <Input placeholder="e.g. Jane Doe" />
          </Form.Item>
          <Form.Item name="role_ids" label="Roles">
            <Select
              mode="multiple"
              allowClear
              placeholder="Assign roles"
              options={roleList.map((r: any) => ({
                value: r.id,
                label: `${r.name}${r.description ? ` — ${r.description}` : ''}`,
              }))}
            />
          </Form.Item>
          <Form.Item name="is_superuser" label="Superuser" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
