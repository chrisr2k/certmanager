import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Card, Table, Tag, Button, Space, Typography, Row, Col,
  Statistic, Progress, Descriptions, Tooltip, Empty
} from 'antd';
import {
  HeartOutlined,
  CheckCircleOutlined,
  ExclamationCircleOutlined,
  CloseCircleOutlined,
  QuestionCircleOutlined,
  ReloadOutlined,
  PlusOutlined,
  ClockCircleOutlined,
} from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import apiClient from '../../api/client';
import HealthTimeline from '../../components/charts/HealthTimeline';

const { Title, Text } = Typography;

export default function CAHealthDashboard() {
  const navigate = useNavigate();

  const { data: health, isLoading, refetch } = useQuery({
    queryKey: ['health-dashboard'],
    queryFn: async () => {
      const { data } = await apiClient.get('/dashboard/health');
      return data;
    },
    refetchInterval: 30_000,
  });

  const authorities = health?.authorities || [];
  const summary = health?.summary || {};
  const timeline = health?.scan_timeline || [];

  const healthPct = summary.total > 0
    ? Math.round(((summary.healthy || 0) / summary.total) * 100)
    : 0;

  const caColumns = [
    {
      title: 'CA Name',
      dataIndex: 'name',
      key: 'name',
      render: (name: string, record: any) => (
        <Space>
          <Tooltip title={`${record.health_status}`}>
            {record.health_status === 'healthy' ? <CheckCircleOutlined style={{ color: '#52c41a' }} />
              : record.health_status === 'degraded' ? <ExclamationCircleOutlined style={{ color: '#faad14' }} />
              : record.health_status === 'unhealthy' ? <CloseCircleOutlined style={{ color: '#ff4d4f' }} />
              : <QuestionCircleOutlined style={{ color: '#d9d9d9' }} />}
          </Tooltip>
          <a onClick={() => navigate(`/authorities`)}>{name}</a>
        </Space>
      ),
    },
    {
      title: 'Type',
      dataIndex: 'ca_type',
      key: 'type',
      width: 130,
      render: (t: string) => {
        const colors: Record<string, string> = { aws_acm: 'orange', azure_keyvault: 'blue', adcs: 'cyan' };
        return <Tag color={colors[t] || 'default'}>{t.replace('_', ' ').toUpperCase()}</Tag>;
      },
    },
    {
      title: 'Health',
      dataIndex: 'health_status',
      key: 'health',
      width: 110,
      render: (h: string) => (
        <Tag
          icon={h === 'healthy' ? <CheckCircleOutlined /> : h === 'degraded' ? <ExclamationCircleOutlined /> : <CloseCircleOutlined />}
          color={h === 'healthy' ? 'success' : h === 'degraded' ? 'warning' : h === 'unhealthy' ? 'error' : 'default'}
        >
          {h}
        </Tag>
      ),
    },
    {
      title: 'Certificates',
      dataIndex: 'certificate_count',
      key: 'certs',
      width: 110,
      align: 'right' as const,
      render: (count: number) => <Text strong>{count}</Text>,
    },
    {
      title: 'Last Scan',
      dataIndex: 'last_scan_at',
      key: 'scan',
      width: 180,
      render: (d: string | null) => d
        ? <Space><ClockCircleOutlined /><Text>{new Date(d).toLocaleString()}</Text></Space>
        : <Text type="secondary">Never</Text>,
    },
    {
      title: 'Scan Status',
      dataIndex: 'last_scan_status',
      key: 'scan_status',
      width: 110,
      render: (s: string | null) => {
        if (!s) return <Tag>pending</Tag>;
        return <Tag color={s === 'success' ? 'green' : s === 'partial' ? 'orange' : 'red'}>{s}</Tag>;
      },
    },
    {
      title: 'Last Error',
      dataIndex: 'last_error',
      key: 'error',
      ellipsis: true,
      width: 200,
      render: (e: string | null) => e
        ? <Tooltip title={e}><Text type="danger" ellipsis style={{ maxWidth: 180 }}>{e}</Text></Tooltip>
        : '-',
    },
  ];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <Title level={3} style={{ margin: 0 }}><HeartOutlined /> CA Health Dashboard</Title>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={() => refetch()}>Refresh</Button>
          <Button type="primary" icon={<PlusOutlined />}>Add Authority</Button>
        </Space>
      </div>

      {/* Summary stats */}
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} sm={12} lg={6}>
          <Card size="small" loading={isLoading}>
            <Statistic title="Overall Health" value={healthPct} suffix="%"
              prefix={<HeartOutlined />}
              valueStyle={{ color: healthPct === 100 ? '#52c41a' : healthPct > 70 ? '#faad14' : '#ff4d4f' }}
            />
            <Progress percent={healthPct} showInfo={false}
              strokeColor={healthPct === 100 ? '#52c41a' : healthPct > 70 ? '#faad14' : '#ff4d4f'}
              style={{ marginTop: 8 }}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6} lg={3}>
          <Card size="small" style={{ textAlign: 'center' }} loading={isLoading}>
            <Statistic title="Total CAs" value={summary.total || 0}
              prefix={<HeartOutlined />} valueStyle={{ color: '#1677ff' }} />
          </Card>
        </Col>
        <Col xs={12} sm={6} lg={3}>
          <Card size="small" style={{ textAlign: 'center' }} loading={isLoading}>
            <Statistic title="Healthy" value={summary.healthy || 0}
              prefix={<CheckCircleOutlined />} valueStyle={{ color: '#52c41a' }} />
          </Card>
        </Col>
        <Col xs={12} sm={6} lg={3}>
          <Card size="small" style={{ textAlign: 'center' }} loading={isLoading}>
            <Statistic title="Degraded" value={summary.degraded || 0}
              prefix={<ExclamationCircleOutlined />} valueStyle={{ color: '#faad14' }} />
          </Card>
        </Col>
        <Col xs={12} sm={6} lg={3}>
          <Card size="small" style={{ textAlign: 'center' }} loading={isLoading}>
            <Statistic title="Unhealthy" value={summary.unhealthy || 0}
              prefix={<CloseCircleOutlined />} valueStyle={{ color: summary.unhealthy ? '#ff4d4f' : '#8c8c8c' }} />
          </Card>
        </Col>
      </Row>

      {/* Health timeline chart */}
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col span={24}>
          <Card title="Scan Activity (Last 24 Hours)" loading={isLoading}>
            <HealthTimeline data={timeline} height={280} />
          </Card>
        </Col>
      </Row>

      {/* CA detail table */}
      <Card
        title={`Certificate Authorities (${authorities.length})`}
        loading={isLoading}
      >
        {authorities.length === 0 ? (
          <div style={{ textAlign: 'center', padding: 40 }}>
            <Empty description="No certificate authorities configured" />
            <Button type="primary" style={{ marginTop: 12 }} icon={<PlusOutlined />}>
              Add your first CA
            </Button>
          </div>
        ) : (
          <Table
            dataSource={authorities}
            columns={caColumns}
            rowKey="id"
            pagination={{ pageSize: 25, showTotal: (t) => `${t} authorities` }}
            size="middle"
          />
        )}
      </Card>
    </div>
  );
}
