import React, { useState } from 'react';
import { Table, Input, Select, Tag, Space, Button, Typography, Card } from 'antd';
import { PlusOutlined, SearchOutlined, ReloadOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import apiClient from '../../api/client';

const { Title } = Typography;

export default function CertificateInventory() {
  const navigate = useNavigate();
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<string | undefined>();
  const [typeFilter, setTypeFilter] = useState<string | undefined>();
  const [expiringFilter, setExpiringFilter] = useState<number | undefined>();

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['certificates', page, search, statusFilter, typeFilter, expiringFilter],
    queryFn: async () => {
      const params: Record<string, any> = {
        page,
        page_size: 25,
        sort_by: 'not_after',
        sort_dir: 'asc',
      };
      if (search) params.q = search;
      if (statusFilter) params.status = statusFilter;
      if (typeFilter) params.cert_type = typeFilter;
      if (expiringFilter) params.expiring_in_days = expiringFilter;
      const { data } = await apiClient.get('/certificates', { params });
      return data;
    },
  });

  const columns = [
    {
      title: 'Common Name',
      dataIndex: 'common_name',
      key: 'cn',
      sorter: true,
      render: (text: string, record: any) => (
        <a onClick={() => navigate(`/certificates/${record.id}`)}>{text || 'N/A'}</a>
      ),
    },
    {
      title: 'Issuer',
      dataIndex: 'issuer',
      key: 'issuer',
      ellipsis: true,
      width: 200,
    },
    {
      title: 'Expires',
      dataIndex: 'not_after',
      key: 'expires',
      width: 140,
      render: (date: string) => new Date(date).toLocaleDateString(),
    },
    {
      title: 'Days Left',
      key: 'days_left',
      width: 100,
      render: (_: any, record: any) => {
        const days = Math.ceil((new Date(record.not_after).getTime() - Date.now()) / (1000 * 60 * 60 * 24));
        return <Tag color={days < 0 ? 'red' : days <= 30 ? 'orange' : days <= 90 ? 'blue' : 'green'}>{days}d</Tag>;
      },
    },
    {
      title: 'Type',
      dataIndex: 'cert_type',
      key: 'type',
      width: 120,
      render: (t: string) => t ? <Tag>{t}</Tag> : '-',
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (status: string) => (
        <Tag color={status === 'active' ? 'green' : status === 'expired' ? 'red' : 'default'}>
          {status}
        </Tag>
      ),
    },
    {
      title: 'Source',
      dataIndex: 'source_type',
      key: 'source',
      width: 120,
      render: (s: string) => s.replace('_', ' ').toUpperCase(),
    },
  ];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <Title level={3} style={{ margin: 0 }}>Certificate Inventory</Title>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={() => refetch()}>Refresh</Button>
          <Button type="primary" icon={<PlusOutlined />}>Add Certificate</Button>
        </Space>
      </div>

      <Card>
        <Space style={{ marginBottom: 16, flexWrap: 'wrap' }}>
          <Input
            placeholder="Search certificates..."
            prefix={<SearchOutlined />}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{ width: 300 }}
            allowClear
          />
          <Select
            placeholder="Status"
            value={statusFilter}
            onChange={setStatusFilter}
            allowClear
            style={{ width: 140 }}
            options={[
              { value: 'active', label: 'Active' },
              { value: 'expired', label: 'Expired' },
              { value: 'revoked', label: 'Revoked' },
            ]}
          />
          <Select
            placeholder="Type"
            value={typeFilter}
            onChange={setTypeFilter}
            allowClear
            style={{ width: 140 }}
            options={[
              { value: 'server', label: 'Server' },
              { value: 'client', label: 'Client' },
              { value: 'ca', label: 'CA' },
              { value: 'code_signing', label: 'Code Signing' },
            ]}
          />
          <Select
            placeholder="Expiring"
            value={expiringFilter}
            onChange={setExpiringFilter}
            allowClear
            style={{ width: 160 }}
            options={[
              { value: 7, label: 'Within 7 days' },
              { value: 30, label: 'Within 30 days' },
              { value: 60, label: 'Within 60 days' },
              { value: 90, label: 'Within 90 days' },
            ]}
          />
        </Space>

        <Table
          dataSource={data?.items || []}
          columns={columns}
          rowKey="id"
          loading={isLoading}
          pagination={{
            current: page,
            pageSize: 25,
            total: data?.total || 0,
            onChange: setPage,
            showTotal: (total) => `${total} certificates`,
          }}
          onRow={(record) => ({
            onClick: () => navigate(`/certificates/${record.id}`),
            style: { cursor: 'pointer' },
          })}
        />
      </Card>
    </div>
  );
}
