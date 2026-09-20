import React, { useState } from 'react';
import { Card, Collapse, Table, Tag, Button, Space, Typography, Row, Col, Statistic, Badge, Descriptions, Progress, Modal, Form, Input, message } from 'antd';
import {
  PlusOutlined,
  GlobalOutlined,
  BankOutlined,
  NodeIndexOutlined,
  SafetyCertificateOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  ExclamationCircleOutlined,
} from '@ant-design/icons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { getEnveloped, default as apiClient } from '../../api/client';
import TopologyGraph from '../../components/charts/TopologyGraph';

const { Title, Text } = Typography;
const { Panel } = Collapse;

export default function DatacentersList() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [addOpen, setAddOpen] = useState(false);
  const [addForm] = Form.useForm();

  // Topology includes DCs + CAs + Agents
  const { data: topology, isLoading } = useQuery({
    queryKey: ['topology-full'],
    queryFn: async () => {
      return getEnveloped('/dashboard/topology');
    },
    refetchInterval: 30_000,
  });

  const datacenters = topology?.datacenters || [];
  const summary = topology?.summary || {};

  const createMutation = useMutation({
    mutationFn: (values: { name: string; code: string; location?: string }) =>
      apiClient.post('/datacenters', values),
    onSuccess: () => {
      message.success('Datacenter created');
      setAddOpen(false);
      addForm.resetFields();
      queryClient.invalidateQueries({ queryKey: ['topology-full'] });
    },
  });

  const handleAdd = () => {
    addForm.resetFields();
    setAddOpen(true);
  };

  const caColumns = [
    { title: 'Name', dataIndex: 'name', key: 'name' },
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
      width: 100,
      render: (h: string) => (
        <Tag color={h === 'healthy' ? 'green' : h === 'degraded' ? 'orange' : h === 'unhealthy' ? 'red' : 'default'}>
          {h}
        </Tag>
      ),
    },
    {
      title: 'Last Scan',
      dataIndex: 'last_scan_at',
      key: 'scan',
      width: 170,
      render: (d: string | null) => d ? new Date(d).toLocaleString() : <Text type="secondary">Never</Text>,
    },
    {
      title: 'Status',
      dataIndex: 'last_scan_status',
      key: 'scan_status',
      width: 90,
      render: (s: string | null) => {
        if (!s) return <Tag>pending</Tag>;
        return <Tag color={s === 'success' ? 'green' : s === 'partial' ? 'orange' : 'red'}>{s}</Tag>;
      },
    },
  ];

  const agentColumns = [
    { title: 'Name', dataIndex: 'name', key: 'name' },
    {
      title: 'Type', dataIndex: 'agent_type', key: 'type', width: 130,
      render: (t: string) => t.replace('_', ' ').toUpperCase(),
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (s: string) => <Badge status={s === 'online' ? 'success' : s === 'offline' ? 'error' : 'warning'} text={s} />,
    },
    {
      title: 'Approved',
      dataIndex: 'is_approved',
      key: 'approved',
      width: 90,
      render: (a: boolean) => <Tag color={a ? 'green' : 'default'}>{a ? 'Yes' : 'No'}</Tag>,
    },
    { title: 'Hostname', dataIndex: 'hostname', key: 'hostname', ellipsis: true },
    {
      title: 'Last Heartbeat',
      dataIndex: 'last_heartbeat_at',
      key: 'heartbeat',
      width: 170,
      render: (d: string | null) => d ? new Date(d).toLocaleString() : <Text type="secondary">Never</Text>,
    },
  ];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <Title level={3} style={{ margin: 0 }}>Datacenter Topology</Title>
        <Space>
          <Button type="primary" icon={<PlusOutlined />} onClick={handleAdd}>Add Datacenter</Button>
        </Space>
      </div>

      {/* Summary row */}
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={12} sm={6} lg={3}>
          <Card size="small" style={{ textAlign: 'center' }}>
            <Statistic title="DCs" value={summary.total_datacenters || 0} prefix={<GlobalOutlined />} valueStyle={{ color: '#722ed1' }} />
          </Card>
        </Col>
        <Col xs={12} sm={6} lg={3}>
          <Card size="small" style={{ textAlign: 'center' }}>
            <Statistic title="CAs" value={summary.total_authorities || 0} prefix={<BankOutlined />} valueStyle={{ color: '#1677ff' }} />
          </Card>
        </Col>
        <Col xs={12} sm={6} lg={3}>
          <Card size="small" style={{ textAlign: 'center' }}>
            <Statistic title="Healthy CAs" value={summary.healthy_cas || 0}
              prefix={<CheckCircleOutlined />}
              suffix={summary.total_authorities ? `/ ${summary.total_authorities}` : ''}
              valueStyle={{ color: '#52c41a' }}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6} lg={3}>
          <Card size="small" style={{ textAlign: 'center' }}>
            <Statistic title="Unhealthy" value={(summary.unhealthy_cas || 0) + (summary.degraded_cas || 0)}
              prefix={<ExclamationCircleOutlined />}
              valueStyle={{ color: (summary.unhealthy_cas || 0) > 0 ? '#ff4d4f' : '#faad14' }}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6} lg={3}>
          <Card size="small" style={{ textAlign: 'center' }}>
            <Statistic title="Agents Online" value={summary.online_agents || 0}
              prefix={<NodeIndexOutlined />}
              suffix={summary.total_agents ? `/ ${summary.total_agents}` : ''}
              valueStyle={{ color: '#13c2c2' }}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6} lg={3}>
          <Card size="small" style={{ textAlign: 'center' }}>
            <Statistic title="Offline" value={summary.offline_agents || 0}
              prefix={<CloseCircleOutlined />}
              valueStyle={{ color: summary.offline_agents ? '#ff4d4f' : '#8c8c8c' }}
            />
          </Card>
        </Col>
      </Row>

      {/* Topology graph */}
      <Card loading={isLoading} style={{ marginBottom: 24 }}>
        <TopologyGraph datacenters={datacenters} height={400} />
      </Card>

      {/* Per-DC detail */}
      <Title level={4}>Datacenter Details</Title>

      {datacenters.map((dc: any) => {
        const healthyCAs = dc.authorities.filter((c: any) => c.health_status === 'healthy').length;
        const totalCAs = dc.authorities.length;

        return (
          <Card
            key={dc.id}
            style={{ marginBottom: 16 }}
            title={
              <Space>
                <GlobalOutlined />
                <span>{dc.name}</span>
                <Tag color="geekblue">{dc.code}</Tag>
                {dc.location && <Text type="secondary">— {dc.location}</Text>}
                <Badge status={dc.is_active ? 'success' : 'default'} text={dc.is_active ? 'Active' : 'Inactive'} />
              </Space>
            }
            extra={
              <Space>
                <Text type="secondary">
                  <SafetyCertificateOutlined /> {dc.certificate_counts?.total || 0} certificates
                  ({dc.certificate_counts?.active || 0} active)
                </Text>
              </Space>
            }
          >
            {/* Health progress bar */}
            {totalCAs > 0 && (
              <div style={{ marginBottom: 16 }}>
                <Text strong>CA Health: </Text>
                <Progress
                  percent={Math.round((healthyCAs / totalCAs) * 100)}
                  format={() => `${healthyCAs}/${totalCAs} healthy`}
                  strokeColor={healthyCAs === totalCAs ? '#52c41a' : healthyCAs >= totalCAs * 0.5 ? '#faad14' : '#ff4d4f'}
                  style={{ maxWidth: 400 }}
                />
              </div>
            )}

            <Collapse ghost>
              {/* Certificate Authorities */}
              {dc.authorities.length > 0 && (
                <Panel header={<><BankOutlined /> Certificate Authorities ({dc.authorities.length})</>} key="cas">
                  <Table
                    dataSource={dc.authorities}
                    columns={caColumns}
                    rowKey="id"
                    pagination={false}
                    size="small"
                  />
                </Panel>
              )}

              {/* Agents */}
              {dc.agents.length > 0 && (
                <Panel header={<><NodeIndexOutlined /> Agents ({dc.agents.length})</>} key="agents">
                  <Table
                    dataSource={dc.agents}
                    columns={agentColumns}
                    rowKey="id"
                    pagination={false}
                    size="small"
                  />
                </Panel>
              )}

              {dc.authorities.length === 0 && dc.agents.length === 0 && (
                <Text type="secondary">No CAs or agents configured for this datacenter.</Text>
              )}
            </Collapse>
          </Card>
        );
      })}

      {datacenters.length === 0 && (
        <Card>
          <div style={{ textAlign: 'center', padding: 40, color: '#8c8c8c' }}>
            <GlobalOutlined style={{ fontSize: 48 }} />
            <div style={{ marginTop: 12, fontSize: 16 }}>No datacenters configured</div>
            <Button type="primary" style={{ marginTop: 12 }} onClick={handleAdd}>Add your first datacenter</Button>
          </div>
        </Card>
      )}

      <Modal
        title="Add Datacenter"
        open={addOpen}
        onOk={() => addForm.submit()}
        confirmLoading={createMutation.isPending}
        onCancel={() => setAddOpen(false)}
        okText="Create"
      >
        <Form
          form={addForm}
          layout="vertical"
          onFinish={(values) => createMutation.mutate(values)}
        >
          <Form.Item
            name="name"
            label="Name"
            rules={[{ required: true, message: 'Name is required' }]}
          >
            <Input placeholder="e.g. Berlin DC" autoFocus />
          </Form.Item>
          <Form.Item
            name="code"
            label="Code"
            tooltip="Short unique code used during agent registration"
            rules={[
              { required: true, message: 'Code is required' },
              { pattern: /^[a-z0-9-]+$/, message: 'Lowercase letters, digits, hyphens only' },
            ]}
          >
            <Input placeholder="e.g. ber" />
          </Form.Item>
          <Form.Item name="location" label="Location">
            <Input placeholder="e.g. Berlin, Germany (optional)" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
