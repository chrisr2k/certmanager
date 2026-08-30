import React from 'react';
import { Card, Table, Tag, Button, Space, Typography } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import apiClient from '../../api/client';

const { Title } = Typography;

export default function AdminUsers() {
  const { data, isLoading } = useQuery({
    queryKey: ['users'],
    queryFn: async () => {
      const { data } = await apiClient.get('/users');
      return data.data || [];
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

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <Title level={3} style={{ margin: 0 }}>Users</Title>
        <Button type="primary" icon={<PlusOutlined />}>Add User</Button>
      </div>
      <Card>
        <Table dataSource={data} columns={columns} rowKey="id" loading={isLoading} pagination={{ pageSize: 25 }} />
      </Card>
    </div>
  );
}
