import React from 'react';
import { Card, Table, Tag, Typography } from 'antd';
import { useQuery } from '@tanstack/react-query';
import apiClient from '../../api/client';

const { Title } = Typography;

export default function AlertsEvents() {
  const { data, isLoading } = useQuery({
    queryKey: ['alert-events'],
    queryFn: async () => {
      const { data } = await apiClient.get('/alerts/events', { params: { page_size: 50 } });
      return data.data || [];
    },
    refetchInterval: 30_000,
  });

  const columns = [
    {
      title: 'Title',
      dataIndex: 'title',
      key: 'title',
      render: (t: string, r: any) => (
        <span>
          {!r.is_acknowledged && <Tag color="red" style={{ marginRight: 8 }}>NEW</Tag>}
          {t}
        </span>
      ),
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
      title: 'Type',
      dataIndex: 'event_type',
      key: 'type',
      width: 120,
    },
    {
      title: 'Acknowledged',
      dataIndex: 'is_acknowledged',
      key: 'acked',
      width: 120,
      render: (a: boolean) => <Tag color={a ? 'green' : 'default'}>{a ? 'Yes' : 'No'}</Tag>,
    },
    {
      title: 'Time',
      dataIndex: 'created_at',
      key: 'time',
      width: 180,
      render: (d: string) => new Date(d).toLocaleString(),
    },
  ];

  return (
    <div>
      <Title level={3}>Alert Events</Title>
      <Card>
        <Table dataSource={data} columns={columns} rowKey="id" loading={isLoading} pagination={{ pageSize: 25 }} />
      </Card>
    </div>
  );
}
