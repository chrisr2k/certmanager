import React from 'react';
import { Row, Col, Card, Statistic, Table, Tag, Typography, Space, Progress, Tooltip, Badge } from 'antd';
import {
  SafetyCertificateOutlined,
  WarningOutlined,
  CheckCircleOutlined,
  ClockCircleOutlined,
  GlobalOutlined,
  CloudServerOutlined,
  NodeIndexOutlined,
  HeartOutlined,
  ApiOutlined,
  CloseCircleOutlined,
} from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import apiClient, { getEnveloped } from '../api/client';
import TopologyGraph from '../components/charts/TopologyGraph';
import HealthTimeline from '../components/charts/HealthTimeline';
import ExpiryGantt from '../components/charts/ExpiryGantt';

const { Title, Text } = Typography;

export default function DashboardPage() {
  const navigate = useNavigate();

  // Certificate stats
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['certificate-stats'],
    queryFn: async () => {
      const { data } = await apiClient.get('/certificates/stats');
      return data;
    },
    refetchInterval: 60_000,
  });

  // Topology
  const { data: topology, isLoading: topoLoading } = useQuery({
    queryKey: ['topology'],
    queryFn: async () => {
      return getEnveloped('/dashboard/topology');
    },
    refetchInterval: 30_000,
  });

  // Health overview
  const { data: health, isLoading: healthLoading } = useQuery({
    queryKey: ['health-overview'],
    queryFn: async () => {
      return getEnveloped('/dashboard/health');
    },
    refetchInterval: 30_000,
  });

  // Expiring certs
  const { data: expiring } = useQuery({
    queryKey: ['expiring-certs-dashboard'],
    queryFn: async () => {
      const { data } = await apiClient.get('/certificates', {
        params: { expiring_in_days: 90, page_size: 20, sort_by: 'not_after', sort_dir: 'asc' },
      });
      return data.items || [];
    },
  });

  const isLoading = statsLoading || topoLoading || healthLoading;
  const topoSummary = topology?.summary || {};
  const healthSummary = health?.summary || {};
  const datacenters = topology?.datacenters || [];
  const healthTimeline = health?.scan_timeline || [];

  const statCards = [
    {
      title: 'Total Certificates',
      value: stats?.total || 0,
      icon: <SafetyCertificateOutlined />,
      color: '#1677ff',
    },
    {
      title: 'Active',
      value: stats?.active || 0,
      icon: <CheckCircleOutlined />,
      color: '#52c41a',
    },
    {
      title: 'Expiring ≤30d',
      value: stats?.expiring_in_30_days || 0,
      icon: <WarningOutlined />,
      color: '#faad14',
    },
    {
      title: 'Expired',
      value: stats?.expired || 0,
      icon: <ClockCircleOutlined />,
      color: '#ff4d4f',
    },
    {
      title: 'Healthy CAs',
      value: healthSummary.healthy || 0,
      icon: <HeartOutlined />,
      color: '#52c41a',
      suffix: healthSummary.total ? ` / ${healthSummary.total}` : '',
    },
    {
      title: 'Datacenters',
      value: topoSummary.total_datacenters || 0,
      icon: <GlobalOutlined />,
      color: '#722ed1',
    },
    {
      title: 'Agents Online',
      value: topoSummary.online_agents || 0,
      icon: <NodeIndexOutlined />,
      color: '#13c2c2',
      suffix: topoSummary.total_agents ? ` / ${topoSummary.total_agents}` : '',
    },
    {
      title: 'Scans (24h)',
      value: healthSummary.scans_last_24h || 0,
      icon: <ApiOutlined />,
      color: '#1677ff',
    },
  ];

  const dcColumns = [
    {
      title: 'Datacenter',
      dataIndex: 'name',
      key: 'name',
      render: (name: string, record: any) => (
        <Space>
          <Badge status={record.is_active ? 'success' : 'default'} />
          <a onClick={() => navigate('/datacenters')}>{name}</a>
          <Text type="secondary" style={{ fontSize: 11 }}>({record.code})</Text>
        </Space>
      ),
    },
    {
      title: 'Certs',
      dataIndex: ['certificate_counts', 'total'],
      key: 'certs',
      width: 70,
    },
    {
      title: 'CAs',
      key: 'cas',
      width: 150,
      render: (_: any, record: any) => {
        const cas = record.authorities || [];
        const healthy = cas.filter((c: any) => c.health_status === 'healthy').length;
        const unhealthy = cas.filter((c: any) => c.health_status === 'unhealthy').length;
        return (
          <Space size={4}>
            {cas.map((ca: any) => (
              <Tooltip key={ca.id} title={`${ca.name} (${ca.ca_type}) — ${ca.health_status}`}>
                <Badge
                  status={
                    ca.health_status === 'healthy' ? 'success'
                    : ca.health_status === 'degraded' ? 'warning'
                    : ca.health_status === 'unhealthy' ? 'error'
                    : 'default'
                  }
                />
              </Tooltip>
            ))}
            <Text type="secondary" style={{ fontSize: 11 }}>{cas.length} CA{cas.length !== 1 ? 's' : ''}</Text>
          </Space>
        );
      },
    },
    {
      title: 'Agents',
      key: 'agents',
      width: 80,
      render: (_: any, record: any) => {
        const agents = record.agents || [];
        const online = agents.filter((a: any) => a.status === 'online').length;
        return (
          <Text>
            <span style={{ color: '#52c41a' }}>{online}</span>
            <span style={{ color: '#8c8c8c' }}>/{agents.length}</span>
          </Text>
        );
      },
    },
    {
      title: 'Location',
      dataIndex: 'location',
      key: 'location',
      ellipsis: true,
      width: 150,
    },
  ];

  const healthyCount = healthSummary.healthy || 0;
  const degradedCount = healthSummary.degraded || 0;
  const unhealthyCount = healthSummary.unhealthy || 0;
  const healthTotal = healthSummary.total || 1;
  const healthPct = Math.round((healthyCount / healthTotal) * 100);

  return (
    <div>
      <Title level={3}>Dashboard</Title>

      {/* Stat cards */}
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        {statCards.map((card) => (
          <Col xs={24} sm={12} md={6} lg={3} key={card.title}>
            <Card loading={isLoading} size="small" style={{ textAlign: 'center' }}>
              <Statistic
                title={card.title}
                value={card.value}
                suffix={card.suffix}
                valueStyle={{ fontSize: 24, color: card.color }}
                prefix={<span style={{ color: card.color, fontSize: 16 }}>{card.icon}</span>}
              />
            </Card>
          </Col>
        ))}
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        {/* CA Health overview */}
        <Col xs={24} lg={8}>
          <Card title={<><HeartOutlined /> CA Health</>} loading={isLoading}>
            <div style={{ textAlign: 'center', marginBottom: 16 }}>
              <Progress
                type="circle"
                percent={healthPct}
                format={() => `${healthyCount}/${healthTotal}`}
                strokeColor={healthPct === 100 ? '#52c41a' : healthPct > 70 ? '#faad14' : '#ff4d4f'}
              />
              <div style={{ marginTop: 12 }}>
                <Space>
                  <Badge status="success" text={`${healthyCount} healthy`} />
                  <Badge status="warning" text={`${degradedCount} degraded`} />
                  <Badge status="error" text={`${unhealthyCount} unhealthy`} />
                </Space>
              </div>
            </div>

            <div style={{ borderTop: '1px solid #f0f0f0', paddingTop: 12 }}>
              <Text strong style={{ fontSize: 13 }}>Total certificates managed: </Text>
              <Text style={{ fontSize: 13 }}>{healthSummary.total_certificates || 0}</Text>
            </div>

            <HealthTimeline data={healthTimeline} height={180} />
          </Card>
        </Col>

        {/* Datacenter overview table */}
        <Col xs={24} lg={8}>
          <Card
            title={<><GlobalOutlined /> Datacenters</>}
            extra={<a onClick={() => navigate('/datacenters')}>Manage</a>}
            loading={isLoading}
          >
            <Table
              dataSource={datacenters}
              columns={dcColumns}
              rowKey="id"
              pagination={false}
              size="small"
              scroll={{ y: 240 }}
            />
          </Card>
        </Col>

        {/* Quick alerts / CA issues */}
        <Col xs={24} lg={8}>
          <Card title={<><WarningOutlined /> Issues</>} loading={isLoading}>
            {unhealthyCount > 0 && (
              <div style={{ marginBottom: 12 }}>
                <Badge status="error" text={`${unhealthyCount} unhealthy CAs`} />
              </div>
            )}
            {degradedCount > 0 && (
              <div style={{ marginBottom: 12 }}>
                <Badge status="warning" text={`${degradedCount} degraded CAs`} />
              </div>
            )}
            {(stats?.expiring_in_30_days || 0) > 0 && (
              <div style={{ marginBottom: 12 }}>
                <Badge status="warning" text={`${stats?.expiring_in_30_days} certs expiring in ≤30 days`} />
              </div>
            )}
            {(stats?.expired || 0) > 0 && (
              <div style={{ marginBottom: 12 }}>
                <Badge status="error" text={`${stats?.expired} expired certificates`} />
              </div>
            )}
            {unhealthyCount === 0 && degradedCount === 0 &&
              (stats?.expiring_in_30_days || 0) === 0 && (stats?.expired || 0) === 0 && (
              <div style={{ color: '#52c41a', textAlign: 'center', padding: 20 }}>
                <CheckCircleOutlined style={{ fontSize: 32 }} />
                <div style={{ marginTop: 8 }}>All systems healthy</div>
              </div>
            )}
          </Card>
        </Col>
      </Row>

      {/* Topology graph */}
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col span={24}>
          <Card
            title={<><CloudServerOutlined /> Multi-Datacenter Topology</>}
            loading={isLoading}
          >
            <TopologyGraph datacenters={datacenters} height={350} />
          </Card>
        </Col>
      </Row>

      {/* Expiry Gantt */}
      <Row gutter={[16, 16]}>
        <Col span={24}>
          <Card
            title="Certificate Expiry Timeline (90 days)"
            extra={<a onClick={() => navigate('/certificates')}>View All</a>}
            loading={isLoading}
          >
            <ExpiryGantt data={expiring || []} days={90} height={300} />
          </Card>
        </Col>
      </Row>
    </div>
  );
}
