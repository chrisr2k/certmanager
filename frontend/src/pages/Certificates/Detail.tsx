import React from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Card, Descriptions, Tag, Button, Space, Typography, Spin, Timeline } from 'antd';
import { ArrowLeftOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import apiClient from '../../api/client';

const { Title } = Typography;

export default function CertificateDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const { data: cert, isLoading } = useQuery({
    queryKey: ['certificate', id],
    queryFn: async () => {
      const { data } = await apiClient.get(`/certificates/${id}`);
      return data;
    },
    enabled: !!id,
  });

  if (isLoading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', padding: 100 }}>
        <Spin size="large" />
      </div>
    );
  }

  if (!cert) {
    return <Typography.Text type="danger">Certificate not found</Typography.Text>;
  }

  const daysLeft = Math.ceil(
    (new Date(cert.not_after).getTime() - Date.now()) / (1000 * 60 * 60 * 24)
  );

  return (
    <div>
      <Space style={{ marginBottom: 16 }}>
        <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/certificates')}>
          Back
        </Button>
        <Title level={4} style={{ margin: 0 }}>
          {cert.common_name || cert.subject || 'Certificate Detail'}
        </Title>
        <Tag color={daysLeft < 0 ? 'red' : daysLeft <= 30 ? 'orange' : 'green'}>
          {daysLeft < 0 ? `Expired ${Math.abs(daysLeft)}d ago` : `${daysLeft}d remaining`}
        </Tag>
      </Space>

      <Card title="Certificate Details" style={{ marginBottom: 16 }}>
        <Descriptions bordered column={2}>
          <Descriptions.Item label="Common Name">{cert.common_name || 'N/A'}</Descriptions.Item>
          <Descriptions.Item label="Status">
            <Tag color={cert.status === 'active' ? 'green' : 'red'}>{cert.status}</Tag>
          </Descriptions.Item>
          <Descriptions.Item label="Subject" span={2}>
            {cert.subject || 'N/A'}
          </Descriptions.Item>
          <Descriptions.Item label="Issuer" span={2}>
            {cert.issuer || 'N/A'}
          </Descriptions.Item>
          <Descriptions.Item label="Serial Number">
            {cert.serial_number || 'N/A'}
          </Descriptions.Item>
          <Descriptions.Item label="Thumbprint (SHA-256)">
            <code style={{ fontSize: 11 }}>{cert.thumbprint_sha256 || 'N/A'}</code>
          </Descriptions.Item>
          <Descriptions.Item label="Valid From">
            {new Date(cert.not_before).toLocaleString()}
          </Descriptions.Item>
          <Descriptions.Item label="Valid Until">
            {new Date(cert.not_after).toLocaleString()}
          </Descriptions.Item>
          <Descriptions.Item label="Key Algorithm">{cert.key_algorithm || 'N/A'}</Descriptions.Item>
          <Descriptions.Item label="Signature Algorithm">{cert.signature_algorithm || 'N/A'}</Descriptions.Item>
          <Descriptions.Item label="Type">{cert.cert_type || 'N/A'}</Descriptions.Item>
          <Descriptions.Item label="Wildcard">{cert.is_wildcard ? 'Yes' : 'No'}</Descriptions.Item>
          <Descriptions.Item label="Source">{cert.source_type?.replace('_', ' ').toUpperCase()}</Descriptions.Item>
          <Descriptions.Item label="Source Detail">
            <pre style={{ fontSize: 11, margin: 0 }}>{JSON.stringify(cert.source_detail, null, 2)}</pre>
          </Descriptions.Item>
          <Descriptions.Item label="SANs" span={2}>
            {cert.sans?.length ? cert.sans.join(', ') : 'None'}
          </Descriptions.Item>
          <Descriptions.Item label="Owner">{cert.owner || 'Unassigned'}</Descriptions.Item>
          <Descriptions.Item label="Tags">
            {Object.entries(cert.tags || {}).length
              ? Object.entries(cert.tags).map(([k, v]) => (
                  <Tag key={k}>{`${k}: ${v}`}</Tag>
                ))
              : 'None'}
          </Descriptions.Item>
          <Descriptions.Item label="First Seen">
            {new Date(cert.first_seen_at).toLocaleString()}
          </Descriptions.Item>
          <Descriptions.Item label="Last Seen">
            {new Date(cert.last_seen_at).toLocaleString()}
          </Descriptions.Item>
        </Descriptions>
      </Card>

      <Card title="Validity Timeline">
        <Timeline
          items={[
            {
              color: cert.status === 'active' ? 'green' : 'gray',
              children: `Issued: ${new Date(cert.not_before).toLocaleDateString()}`,
            },
            {
              color: cert.status === 'active' && daysLeft > 90 ? 'blue' : 'gray',
              children: `Current: Active (${daysLeft}d remaining)`,
            },
            {
              color: daysLeft <= 30 ? 'red' : daysLeft <= 90 ? 'orange' : 'blue',
              children: `Expires: ${new Date(cert.not_after).toLocaleDateString()}`,
            },
          ]}
        />
      </Card>
    </div>
  );
}
