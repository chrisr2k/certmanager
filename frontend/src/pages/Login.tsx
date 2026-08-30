import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card, Form, Input, Button, Typography, message, Divider } from 'antd';
import { LockOutlined, MailOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import { useAuth } from '../store/auth';

const { Title, Text } = Typography;

export default function LoginPage() {
  const [loading, setLoading] = useState(false);
  const [mfaRequired, setMfaRequired] = useState(false);
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();

  // Redirect if already authenticated
  React.useEffect(() => {
    if (isAuthenticated) {
      navigate('/', { replace: true });
    }
  }, [isAuthenticated, navigate]);

  const handleSubmit = async (values: { email: string; password: string; mfa_code?: string }) => {
    setLoading(true);
    try {
      await login(values.email, values.password, values.mfa_code);
      message.success('Login successful');
      navigate('/', { replace: true });
    } catch (err: any) {
      const errorData = err.response?.data;
      if (errorData?.mfa_required) {
        setMfaRequired(true);
        message.info('MFA code required');
      } else {
        message.error(errorData?.message || 'Login failed');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        minHeight: '100vh',
        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
      }}
    >
      <Card style={{ width: 420, boxShadow: '0 8px 24px rgba(0,0,0,0.15)' }}>
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <SafetyCertificateOutlined style={{ fontSize: 48, color: '#1677ff' }} />
          <Title level={2} style={{ marginTop: 12, marginBottom: 4 }}>
            CertManager
          </Title>
          <Text type="secondary">Enterprise Certificate Management</Text>
        </div>

        <Form
          name="login"
          onFinish={handleSubmit}
          layout="vertical"
          size="large"
          initialValues={{ email: 'admin@certmanager.local' }}
        >
          <Form.Item
            name="email"
            rules={[{ required: true, message: 'Please enter your email' }]}
          >
            <Input prefix={<MailOutlined />} placeholder="Email" autoComplete="email" />
          </Form.Item>

          <Form.Item
            name="password"
            rules={[{ required: true, message: 'Please enter your password' }]}
          >
            <Input.Password
              prefix={<LockOutlined />}
              placeholder="Password"
              autoComplete="current-password"
            />
          </Form.Item>

          {mfaRequired && (
            <Form.Item
              name="mfa_code"
              rules={[{ required: true, message: 'Please enter your MFA code' }]}
            >
              <Input
                prefix={<SafetyCertificateOutlined />}
                placeholder="MFA Code"
                maxLength={6}
                autoComplete="one-time-code"
              />
            </Form.Item>
          )}

          <Form.Item>
            <Button type="primary" htmlType="submit" loading={loading} block>
              {mfaRequired ? 'Verify MFA' : 'Sign In'}
            </Button>
          </Form.Item>
        </Form>

        <Divider />
        <Text type="secondary" style={{ display: 'block', textAlign: 'center', fontSize: 12 }}>
          Default: admin@certmanager.local / changeme123
        </Text>
      </Card>
    </div>
  );
}
