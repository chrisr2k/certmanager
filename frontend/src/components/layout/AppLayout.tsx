import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  Layout,
  Menu,
  Button,
  Dropdown,
  Avatar,
  Badge,
  Space,
  Select,
  theme,
} from 'antd';
import {
  DashboardOutlined,
  SafetyCertificateOutlined,
  BankOutlined,
  AlertOutlined,
  GlobalOutlined,
  FileTextOutlined,
  SettingOutlined,
  UserOutlined,
  LogoutOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  CloudServerOutlined,
} from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { useAuth, canAccessAdmin } from '../../store/auth';
import apiClient from '../../api/client';

const { Header, Sider, Content } = Layout;

interface AppLayoutProps {
  children: React.ReactNode;
}

export default function AppLayout({ children }: AppLayoutProps) {
  const [collapsed, setCollapsed] = useState(false);
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const { token: themeToken } = theme.useToken();

  const isAdmin = canAccessAdmin(user);

  // Datacenter selector options come from the live topology. If the call
  // fails or there are no datacenters, the selector is hidden gracefully.
  const { data: topologyDatacenters } = useQuery({
    queryKey: ['topology-nav'],
    queryFn: async () => {
      const { data } = await apiClient.get('/dashboard/topology');
      return data?.data?.datacenters ?? [];
    },
    staleTime: 30_000,
    refetchInterval: 60_000,
  });
  const datacenters: any[] = topologyDatacenters ?? [];

  // Count of unacknowledged alert events for the header badge.
  const { data: unackedEvents } = useQuery({
    queryKey: ['alert-events-badge'],
    queryFn: async () => {
      const { data } = await apiClient.get('/alerts/events', {
        params: { is_acknowledged: false, page_size: 1 },
      });
      return data;
    },
    staleTime: 15_000,
    refetchInterval: 30_000,
  });
  const unackedCount: number = unackedEvents?.total ?? unackedEvents?.data?.length ?? 0;

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const menuItems = [
    {
      key: '/',
      icon: <DashboardOutlined />,
      label: 'Dashboard',
    },
    {
      key: '/certificates',
      icon: <SafetyCertificateOutlined />,
      label: 'Certificates',
    },
    {
      key: 'authorities',
      icon: <BankOutlined />,
      label: 'Authorities',
      children: [
        { key: '/authorities', label: 'All CAs' },
        { key: '/authorities/health', label: 'Health' },
      ],
    },
    {
      key: '/datacenters',
      icon: <GlobalOutlined />,
      label: 'Datacenters',
    },
    {
      key: 'alerts',
      icon: <AlertOutlined />,
      label: 'Alerts',
      children: [
        { key: '/alerts/rules', label: 'Rules' },
        { key: '/alerts/channels', label: 'Channels' },
        { key: '/alerts/events', label: 'Events' },
      ],
    },
    {
      key: '/reports',
      icon: <FileTextOutlined />,
      label: 'Reports',
    },
    ...(isAdmin
      ? [{
          key: 'admin',
          icon: <SettingOutlined />,
          label: 'Admin',
          children: [
            { key: '/admin/users', label: 'Users' },
            { key: '/admin/agents', label: 'Agents' },
            { key: '/audit-log', label: 'Audit Log' },
          ],
        }]
      : []),
  ];

  const userMenuItems = [
    { key: 'profile', icon: <UserOutlined />, label: `${user?.email}` },
    { type: 'divider' as const },
    { key: 'logout', icon: <LogoutOutlined />, label: 'Logout', onClick: handleLogout },
  ];

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider
        trigger={null}
        collapsible
        collapsed={collapsed}
        style={{ background: themeToken.colorBgContainer }}
      >
        <div className="logo" style={{ color: themeToken.colorPrimary }}>
          {collapsed ? 'CM' : 'CertManager'}
        </div>
        <Menu
          mode="inline"
          selectedKeys={[location.pathname]}
          defaultOpenKeys={['authorities', 'alerts', ...(isAdmin ? ['admin'] : [])]}
          items={menuItems}
          onClick={({ key }) => navigate(key)}
          style={{ borderRight: 0 }}
        />
      </Sider>
      <Layout>
        <Header
          style={{
            padding: '0 24px',
            background: themeToken.colorBgContainer,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            borderBottom: `1px solid ${themeToken.colorBorderSecondary}`,
          }}
        >
          <Button
            type="text"
            icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
            onClick={() => setCollapsed(!collapsed)}
          />
          <Space size="middle">
            {/* Datacenter selector — populated from live topology; hidden when unavailable */}
            {datacenters.length > 0 && (
              <Select
                defaultValue="all"
                style={{ width: 160 }}
                options={[
                  { value: 'all', label: 'All Datacenters' },
                  ...datacenters.map((dc) => ({ value: dc.id, label: dc.name })),
                ]}
                prefix={<CloudServerOutlined />}
              />
            )}
            {/* Alert badge — count of unacknowledged alert events */}
            <Badge count={unackedCount} size="small" overflowCount={99}>
              <Button
                type="text"
                icon={<AlertOutlined />}
                onClick={() => navigate('/alerts/events')}
              />
            </Badge>
            {/* User menu */}
            <Dropdown menu={{ items: userMenuItems }} trigger={['click']}>
              <Button type="text" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Avatar size="small" icon={<UserOutlined />} />
                <span>{user?.full_name || user?.email}</span>
              </Button>
            </Dropdown>
          </Space>
        </Header>
        <Content style={{ margin: 0, background: themeToken.colorBgLayout }}>
          <div className="page-container">{children}</div>
        </Content>
      </Layout>
    </Layout>
  );
}
