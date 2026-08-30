import React, { useState } from 'react';
import {
  Card, Table, Tag, Space, Typography, DatePicker, Select, Input,
  Button, Descriptions, Modal,
} from 'antd';
import { SearchOutlined, AuditOutlined, ReloadOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import apiClient from '../api/client';
import dayjs from 'dayjs';

const { Title, Text } = Typography;
const { RangePicker } = DatePicker;

export default function AuditLogPage() {
  const [page, setPage] = useState(1);
  const [eventType, setEventType] = useState<string | undefined>();
  const [resourceType, setResourceType] = useState<string | undefined>();
  const [actorId, setActorId] = useState<string | undefined>();
  const [dateRange, setDateRange] = useState<[string, string] | null>(null);
  const [selectedLog, setSelectedLog] = useState<any>(null);
  const [detailOpen, setDetailOpen] = useState(false);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['audit-logs', page, eventType, resourceType, actorId, dateRange],
    queryFn: async () => {
      const params: Record<string, any> = { page, page_size: 25 };
      if (eventType) params.event_type = eventType;
      if (resourceType) params.resource_type = resourceType;
      if (actorId) params.actor_id = actorId;
      if (dateRange) {
        params.from_date = dateRange[0];
        params.to_date = dateRange[1];
      }
      const { data } = await apiClient.get('/audit-logs', { params });
      return data;
    },
  });

  const logs = data?.data || [];
  const total = data?.total || 0;

  const columns = [
    { title: 'ID', dataIndex: 'id', key: 'id', width: 80 },
    {
      title: 'Event',
      dataIndex: 'event_type',
      key: 'event',
      width: 140,
      render: (t: string) => <Tag>{t}</Tag>,
    },
    {
      title: 'Actor',
      key: 'actor',
      width: 180,
      render: (_: any, r: any) => (
        <Space direction="vertical" size={0}>
          <Text strong>{r.actor_email || 'System'}</Text>
          <Text type="secondary" style={{ fontSize: 11 }}>{r.actor_type} | {r.ip_address || 'N/A'}</Text>
        </Space>
      ),
    },
    {
      title: 'Resource',
      key: 'resource',
      width: 150,
      render: (_: any, r: any) => (
        <Space>
          <Tag>{r.resource_type || 'N/A'}</Tag>
          <Text code style={{ fontSize: 10 }}>{(r.resource_id || '').slice(0, 8)}</Text>
        </Space>
      ),
    },
    {
      title: 'Action',
      dataIndex: 'action',
      key: 'action',
      width: 80,
      render: (a: string) => <Tag color="blue">{a.toUpperCase()}</Tag>,
    },
    {
      title: 'Time',
      dataIndex: 'created_at',
      key: 'time',
      width: 180,
      render: (d: string) => new Date(d).toLocaleString(),
    },
    {
      title: 'Correlation ID',
      dataIndex: 'correlation_id',
      key: 'corr',
      width: 120,
      ellipsis: true,
      render: (c: string | null) => c ? <Text code style={{ fontSize: 10 }}>{c.slice(0, 12)}</Text> : '-',
    },
  ];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <Title level={3} style={{ margin: 0 }}><AuditOutlined /> Audit Log</Title>
        <Button icon={<ReloadOutlined />} onClick={() => refetch()}>Refresh</Button>
      </div>

      <Card>
        <Space style={{ marginBottom: 16 }} wrap>
          <Select
            placeholder="Event Type"
            value={eventType}
            onChange={setEventType}
            allowClear
            style={{ width: 160 }}
            options={[
              { value: 'api.post', label: 'API POST' },
              { value: 'api.get', label: 'API GET' },
              { value: 'api.patch', label: 'API PATCH' },
              { value: 'api.delete', label: 'API DELETE' },
              { value: 'user.login', label: 'User Login' },
            ]}
          />
          <Select
            placeholder="Resource"
            value={resourceType}
            onChange={setResourceType}
            allowClear
            style={{ width: 160 }}
            options={[
              { value: 'certificates', label: 'Certificates' },
              { value: 'authorities', label: 'Authorities' },
              { value: 'alerts', label: 'Alerts' },
              { value: 'agents', label: 'Agents' },
              { value: 'users', label: 'Users' },
            ]}
          />
          <RangePicker
            onChange={(dates) => {
              if (dates && dates[0] && dates[1]) {
                setDateRange([dates[0].toISOString(), dates[1].toISOString()]);
              } else {
                setDateRange(null);
              }
            }}
          />
        </Space>

        <Table
          dataSource={logs}
          columns={columns}
          rowKey="id"
          loading={isLoading}
          pagination={{
            current: page,
            pageSize: 25,
            total,
            onChange: setPage,
            showTotal: (t) => `${t} audit entries`,
          }}
          size="small"
          onRow={(record) => ({
            onClick: () => { setSelectedLog(record); setDetailOpen(true); },
            style: { cursor: 'pointer' },
          })}
        />
      </Card>

      <Modal
        title="Audit Entry Detail"
        open={detailOpen}
        onCancel={() => setDetailOpen(false)}
        footer={<Button onClick={() => setDetailOpen(false)}>Close</Button>}
        width={700}
      >
        {selectedLog && (
          <Descriptions bordered column={2} size="small">
            <Descriptions.Item label="ID">{selectedLog.id}</Descriptions.Item>
            <Descriptions.Item label="Event Type">
              <Tag>{selectedLog.event_type}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="Actor Type">{selectedLog.actor_type}</Descriptions.Item>
            <Descriptions.Item label="Actor ID">
              <Text code>{selectedLog.actor_id || 'N/A'}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="Actor Email">{selectedLog.actor_email || 'N/A'}</Descriptions.Item>
            <Descriptions.Item label="IP Address">{selectedLog.ip_address || 'N/A'}</Descriptions.Item>
            <Descriptions.Item label="Resource Type">{selectedLog.resource_type || 'N/A'}</Descriptions.Item>
            <Descriptions.Item label="Resource ID">
              <Text code>{selectedLog.resource_id || 'N/A'}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="Action">
              <Tag color="blue">{selectedLog.action?.toUpperCase()}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="Correlation ID">
              <Text code>{selectedLog.correlation_id || 'N/A'}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="Timestamp">{new Date(selectedLog.created_at).toLocaleString()}</Descriptions.Item>
            <Descriptions.Item label="User Agent" span={2}>
              <Text style={{ fontSize: 11 }}>{selectedLog.user_agent || 'N/A'}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="Details" span={2}>
              <pre style={{ fontSize: 11, maxHeight: 300, overflow: 'auto', margin: 0 }}>
                {JSON.stringify(selectedLog.details, null, 2)}
              </pre>
            </Descriptions.Item>
          </Descriptions>
        )}
      </Modal>
    </div>
  );
}
