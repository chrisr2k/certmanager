import React, { useState } from 'react';
import {
  Card, Table, Tag, Button, Space, Typography, Descriptions, Modal, message,
  Row, Col, Statistic, Badge, Tooltip, Form, Input
} from 'antd';
import {
  PlusOutlined, ReloadOutlined, CheckCircleOutlined, CloseCircleOutlined,
  NodeIndexOutlined, ClockCircleOutlined, ExclamationCircleOutlined,
  StopOutlined, PlayCircleOutlined, ScanOutlined, GlobalOutlined,
  EditOutlined, DeleteOutlined,
} from '@ant-design/icons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import apiClient from '../../api/client';

const { Title, Text } = Typography;

// ---- TLS Scan Targets sub-component ----
function TLSScanTargets({ agentId, agentType }: { agentId: string; agentType: string }) {
  const [editMode, setEditMode] = useState(false);
  const [cidrs, setCidrs] = useState('');
  const [ports, setPorts] = useState('');

  const { data: targets, isLoading, refetch } = useQuery({
    queryKey: ['scan-targets', agentId],
    queryFn: async () => {
      const { data } = await apiClient.get(`/agents/${agentId}/scan-targets`);
      return data.data ?? {};
    },
    enabled: !!agentId,
  });

  const saveMutation = useMutation({
    mutationFn: async () => {
      const cidrList = cidrs.split('\n').map((s: string) => s.trim()).filter(Boolean);
      const portList = ports.split(',').map((s: string) => parseInt(s.trim())).filter((n: number) => !isNaN(n));
      await apiClient.patch(`/agents/${agentId}/scan-targets`, {
        cidr_ranges: cidrList.length > 0 ? cidrList : undefined,
        ports: portList.length > 0 ? portList : undefined,
      });
    },
    onSuccess: () => {
      message.success('Scan targets updated');
      setEditMode(false);
      refetch();
    },
  });

  const scanMutation = useMutation({
    mutationFn: async () => {
      // Empty body: the backend falls back to the stored scan targets
      await apiClient.post(`/agents/${agentId}/scan-targets/scan`, {});
    },
    onSuccess: (resp: any) => {
      const jobId = resp?.data?.data?.scan_job_id;
      message.success(jobId ? `TLS scan queued: ${jobId.slice(0, 8)}...` : 'TLS scan queued');
    },
  });

  const currentCidrs = targets?.cidr_ranges || [];
  const currentPorts = targets?.ports || [];

  if (isLoading) return <Text type="secondary">Loading scan targets...</Text>;

  if (!editMode) {
    return (
      <div style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
          <Title level={5} style={{ margin: 0 }}><GlobalOutlined /> TLS Scan Targets</Title>
          <Space size="small">
            <Button size="small" icon={<EditOutlined />} onClick={() => {
              setCidrs(currentCidrs.join('\n'));
              setPorts(currentPorts.join(', '));
              setEditMode(true);
            }}>Edit</Button>
            <Button size="small" type="primary" icon={<ScanOutlined />}
              onClick={() => scanMutation.mutate()}
              loading={scanMutation.isPending}
              disabled={currentCidrs.length === 0}
            >
              Scan Now
            </Button>
          </Space>
        </div>
        {currentCidrs.length === 0 ? (
          <Text type="secondary">No CIDR ranges configured. Click Edit to add scan targets.</Text>
        ) : (
          <>
            <div style={{ marginBottom: 8 }}>
              <Text strong>CIDR ranges: </Text>
              {currentCidrs.map((cidr: string) => (
                <Tag key={cidr} color="blue">{cidr}</Tag>
              ))}
            </div>
            <div>
              <Text strong>Ports: </Text>
              {currentPorts.map((p: number) => (
                <Tag key={p}>{p}</Tag>
              ))}
            </div>
            {targets?.scan_schedule && (
              <div style={{ marginTop: 4 }}>
                <Text type="secondary">Schedule: {targets.scan_schedule}</Text>
              </div>
            )}
          </>
        )}
      </div>
    );
  }

  return (
    <div style={{ marginBottom: 16, padding: 12, background: '#f9f9f9', borderRadius: 6 }}>
      <Title level={5} style={{ margin: 0, marginBottom: 8 }}>Edit TLS Scan Targets</Title>
      <Form layout="vertical" size="small">
        <Form.Item label="CIDR Ranges (one per line)">
          <Input.TextArea
            rows={4}
            value={cidrs}
            onChange={(e) => setCidrs(e.target.value)}
            placeholder={"10.0.1.0/24\n172.16.0.0/24\n192.168.0.0/28"}
            style={{ fontFamily: 'monospace', fontSize: 12 }}
          />
          <Text type="secondary" style={{ fontSize: 11 }}>
            Max 256 hosts per range. /16 or smaller recommended.
          </Text>
        </Form.Item>
        <Form.Item label="Ports (comma-separated)">
          <Input
            value={ports}
            onChange={(e) => setPorts(e.target.value)}
            placeholder="443, 8443, 636, 993, 995"
          />
        </Form.Item>
        <Space>
          <Button size="small" type="primary" onClick={() => saveMutation.mutate()}
            loading={saveMutation.isPending}>Save</Button>
          <Button size="small" onClick={() => setEditMode(false)}>Cancel</Button>
        </Space>
      </Form>
    </div>
  );
}

export default function AdminAgents() {
  const queryClient = useQueryClient();
  const [selectedAgent, setSelectedAgent] = useState<any>(null);
  const [detailOpen, setDetailOpen] = useState(false);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['agents'],
    queryFn: async () => {
      const { data } = await apiClient.get('/agents');
      return data.data || [];
    },
    refetchInterval: 15_000,
  });

  // Approve mutation
  const approveMutation = useMutation({
    mutationFn: async (agentId: string) => {
      await apiClient.patch(`/agents/${agentId}/approve`);
    },
    onSuccess: () => {
      message.success('Agent approved');
      queryClient.invalidateQueries({ queryKey: ['agents'] });
    },
  });

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: async (agentId: string) => {
      await apiClient.delete(`/agents/${agentId}`);
    },
    onSuccess: () => {
      message.success('Agent removed');
      queryClient.invalidateQueries({ queryKey: ['agents'] });
      setDetailOpen(false);
    },
  });

  const agents = data || [];

  // Stats
  const online = agents.filter((a: any) => a.status === 'online').length;
  const offline = agents.filter((a: any) => a.status === 'offline').length;
  const unapproved = agents.filter((a: any) => !a.is_approved).length;

  const columns = [
    {
      title: 'Agent',
      dataIndex: 'name',
      key: 'name',
      render: (name: string, record: any) => (
        <Space>
          <Badge
            status={record.status === 'online' ? 'success' : record.status === 'offline' ? 'error' : 'warning'}
          />
          <a onClick={() => { setSelectedAgent(record); setDetailOpen(true); }}>{name}</a>
        </Space>
      ),
    },
    {
      title: 'Type',
      dataIndex: 'agent_type',
      key: 'type',
      width: 130,
      render: (t: string) => <Tag>{t.replace('_', ' ').toUpperCase()}</Tag>,
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 110,
      render: (s: string) => (
        <Tag
          color={s === 'online' ? 'success' : s === 'offline' ? 'error' : s === 'unapproved' ? 'warning' : 'default'}
          icon={s === 'online' ? <CheckCircleOutlined /> : s === 'offline' ? <CloseCircleOutlined /> : undefined}
        >
          {s}
        </Tag>
      ),
    },
    {
      title: 'Approved',
      dataIndex: 'is_approved',
      key: 'approved',
      width: 100,
      render: (a: boolean) => <Tag color={a ? 'green' : 'orange'}>{a ? 'Yes' : 'No'}</Tag>,
    },
    {
      title: 'Hostname',
      dataIndex: 'hostname',
      key: 'hostname',
      ellipsis: true,
      width: 180,
    },
    {
      title: 'IP',
      dataIndex: 'ip_address',
      key: 'ip',
      width: 140,
    },
    {
      title: 'Last Heartbeat',
      dataIndex: 'last_heartbeat_at',
      key: 'heartbeat',
      width: 170,
      render: (d: string | null) => d
        ? <Space><ClockCircleOutlined /><Text>{new Date(d).toLocaleString()}</Text></Space>
        : <Text type="secondary">Never</Text>,
    },
    {
      title: 'Actions',
      key: 'actions',
      width: 160,
      render: (_: any, record: any) => (
        <Space size="small">
          {!record.is_approved && (
            <Tooltip title="Approve agent">
              <Button
                type="link"
                size="small"
                icon={<PlayCircleOutlined />}
                onClick={(e) => { e.stopPropagation(); approveMutation.mutate(record.id); }}
                loading={approveMutation.isPending}
              >
                Approve
              </Button>
            </Tooltip>
          )}
          <Tooltip title="Remove agent">
            <Button
              type="link"
              danger
              size="small"
              icon={<StopOutlined />}
              onClick={(e) => {
                e.stopPropagation();
                Modal.confirm({
                  title: 'Remove Agent',
                  content: `Are you sure you want to remove "${record.name}"? This cannot be undone.`,
                  okText: 'Remove',
                  okType: 'danger',
                  onOk: () => deleteMutation.mutate(record.id),
                });
              }}
            />
          </Tooltip>
        </Space>
      ),
    },
  ];

  // Parse agent config for display
  const configEntries = selectedAgent && typeof selectedAgent === 'object'
    ? Object.entries(selectedAgent).filter(([k]) => !['id', 'name', 'agent_type', 'status', 'is_approved', 'hostname', 'ip_address', 'version', 'last_heartbeat_at', 'last_job_at', 'created_at', 'updated_at'].includes(k))
    : [];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <Title level={3} style={{ margin: 0 }}>Agents</Title>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={() => refetch()}>Refresh</Button>
        </Space>
      </div>

      {/* Summary stats */}
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={12} sm={6}>
          <Card size="small" style={{ textAlign: 'center' }} loading={isLoading}>
            <Statistic title="Total" value={agents.length}
              prefix={<NodeIndexOutlined />} valueStyle={{ color: '#1677ff' }} />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card size="small" style={{ textAlign: 'center' }} loading={isLoading}>
            <Statistic title="Online" value={online}
              prefix={<CheckCircleOutlined />} valueStyle={{ color: '#52c41a' }} />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card size="small" style={{ textAlign: 'center' }} loading={isLoading}>
            <Statistic title="Offline" value={offline}
              prefix={<CloseCircleOutlined />} valueStyle={{ color: offline ? '#ff4d4f' : '#8c8c8c' }} />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card size="small" style={{ textAlign: 'center' }} loading={isLoading}>
            <Statistic title="Unapproved" value={unapproved}
              prefix={<ExclamationCircleOutlined />} valueStyle={{ color: unapproved ? '#faad14' : '#8c8c8c' }} />
          </Card>
        </Col>
      </Row>

      {/* Agent table */}
      <Card loading={isLoading}>
        {agents.length === 0 ? (
          <div style={{ textAlign: 'center', padding: 40, color: '#8c8c8c' }}>
            <NodeIndexOutlined style={{ fontSize: 48 }} />
            <div style={{ marginTop: 12, fontSize: 16 }}>No agents registered</div>
            <Text type="secondary">
              Agents are installed in each datacenter. Use <code>certmanager agent init</code> to set one up.
            </Text>
          </div>
        ) : (
          <Table
            dataSource={agents}
            columns={columns}
            rowKey="id"
            pagination={false}
            size="middle"
            onRow={(record) => ({
              onClick: () => { setSelectedAgent(record); setDetailOpen(true); },
              style: { cursor: 'pointer' },
            })}
          />
        )}
      </Card>

      {/* Agent Detail Modal */}
      <Modal
        title={<Space><NodeIndexOutlined /> {selectedAgent?.name}</Space>}
        open={detailOpen}
        onCancel={() => setDetailOpen(false)}
        width={700}
        footer={[
          !selectedAgent?.is_approved && (
            <Button
              key="approve"
              type="primary"
              icon={<PlayCircleOutlined />}
              onClick={() => approveMutation.mutate(selectedAgent.id)}
              loading={approveMutation.isPending}
            >
              Approve Agent
            </Button>
          ),
          <Button key="close" onClick={() => setDetailOpen(false)}>Close</Button>,
        ]}
      >
        {selectedAgent && (
          <div>
            <Descriptions bordered column={2} size="small" style={{ marginBottom: 16 }}>
              <Descriptions.Item label="Agent ID">
                <Text code>{selectedAgent.id}</Text>
              </Descriptions.Item>
              <Descriptions.Item label="Name">{selectedAgent.name}</Descriptions.Item>
              <Descriptions.Item label="Type">
                <Tag>{(selectedAgent.agent_type || '').replace('_', ' ').toUpperCase()}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="Status">
                <Badge
                  status={selectedAgent.status === 'online' ? 'success' : selectedAgent.status === 'offline' ? 'error' : 'warning'}
                  text={selectedAgent.status}
                />
              </Descriptions.Item>
              <Descriptions.Item label="Approved">
                <Tag color={selectedAgent.is_approved ? 'green' : 'orange'}>
                  {selectedAgent.is_approved ? 'Yes' : 'No'}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="Version">{selectedAgent.version || 'Unknown'}</Descriptions.Item>
              <Descriptions.Item label="Hostname">{selectedAgent.hostname || 'N/A'}</Descriptions.Item>
              <Descriptions.Item label="IP Address">{selectedAgent.ip_address || 'N/A'}</Descriptions.Item>
              <Descriptions.Item label="Last Heartbeat" span={2}>
                {selectedAgent.last_heartbeat_at
                  ? new Date(selectedAgent.last_heartbeat_at).toLocaleString()
                  : 'Never'}
              </Descriptions.Item>
              <Descriptions.Item label="Last Job">
                {selectedAgent.last_job_at
                  ? new Date(selectedAgent.last_job_at).toLocaleString()
                  : 'Never'}
              </Descriptions.Item>
              <Descriptions.Item label="Registered">
                {selectedAgent.created_at
                  ? new Date(selectedAgent.created_at).toLocaleString()
                  : 'Unknown'}
              </Descriptions.Item>
            </Descriptions>

            {/* TLS Scan Targets (for tls_scanner/generic agents) */}
            {(selectedAgent.agent_type === 'tls_scanner' || selectedAgent.agent_type === 'generic') && (
              <TLSScanTargets agentId={selectedAgent.id} agentType={selectedAgent.agent_type} />
            )}

            {configEntries.length > 0 && (
              <>
                <Title level={5}>Configuration</Title>
                <Descriptions bordered column={1} size="small">
                  {configEntries.map(([key, value]) => (
                    <Descriptions.Item key={key} label={key}>
                      {typeof value === 'object'
                        ? <Text code style={{ fontSize: 11 }}>{JSON.stringify(value, null, 2)}</Text>
                        : String(value)}
                    </Descriptions.Item>
                  ))}
                </Descriptions>
              </>
            )}
          </div>
        )}
      </Modal>
    </div>
  );
}
