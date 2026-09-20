import React, { useState } from 'react';
import { Card, Table, Tag, Button, Space, Typography } from 'antd';
import { PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import apiClient from '../../api/client';
import AddAuthorityModal from '../../components/AddAuthorityModal';

const { Title } = Typography;

export default function AuthoritiesList() {
  const [addOpen, setAddOpen] = useState(false);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['authorities'],
    queryFn: async () => {
      const { data } = await apiClient.get('/authorities');
      return data.data || [];
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
    </div>
  );
}
