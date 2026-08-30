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
import { useAuth } from '../../store/auth';

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
    {
      key: 'admin',
      icon: <SettingOutlined />,
      label: 'Admin',
      children: [
        { key: '/admin/users', label: 'Users' },
        { key: '/admin/agents', label: 'Agents' },
        { key: '/audit-log', label: 'Audit Log' },
      ],
    },
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
          defaultOpenKeys={['authorities', 'alerts', 'admin']}
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
            {/* Datacenter selector */}
            <Select
              defaultValue="all"
              style={{ width: 160 }}
              options={[
                { value: 'all', label: 'All Datacenters' },
                { value: 'dc1', label: 'DC1 - us-east' },
                { value: 'dc2', label: 'DC2 - eu-west' },
              ]}
              prefix={<CloudServerOutlined />}
            />
            {/* Alert badge */}
            <Badge count={3} size="small">
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
