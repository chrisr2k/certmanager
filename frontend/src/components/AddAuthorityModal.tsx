import { useState } from 'react';
import { Modal, Form, Input, Select, message } from 'antd';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import apiClient, { getEnveloped } from '../api/client';

const CA_TYPES = [
  { value: 'aws_acm', label: 'AWS ACM' },
  { value: 'azure_keyvault', label: 'Azure Key Vault' },
  { value: 'adcs', label: 'Active Directory CS' },
  { value: 'acme', label: "Let's Encrypt / ACME" },
];

const ACME_DIRECTORIES = [
  { value: 'https://acme-v02.api.letsencrypt.org/directory', label: "Let's Encrypt (production)" },
  { value: 'https://acme-staging-v02.api.letsencrypt.org/directory', label: "Let's Encrypt (staging — recommended for testing)" },
  { value: 'custom', label: 'Custom directory URL' },
];

export default function AddAuthorityModal({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const [form] = Form.useForm();

  const { data: datacenters } = useQuery({
    queryKey: ['datacenters-list'],
    queryFn: () => getEnveloped('/datacenters'),
    enabled: open,
  });

  const createMutation = useMutation({
    mutationFn: (values: any) => apiClient.post('/authorities', values),
    onSuccess: () => {
      message.success('Authority created');
      form.resetFields();
      onClose();
      queryClient.invalidateQueries();
    },
  });

  // Build the provider config dict from the type-specific form fields.
  // Only filled fields are included; secrets are encrypted at rest by the
  // backend before the config is stored.
  const handleFinish = (values: any) => {
    const config: Record<string, any> = {};
    const pick = (keys: string[]) => {
      for (const k of keys) {
        if (values[k] !== undefined && values[k] !== null && values[k] !== '') {
          config[k] = values[k];
        }
      }
    };
    switch (values.ca_type) {
      case 'aws_acm':
        pick(['account_id', 'regions', 'role_arn', 'external_id', 'profile_name']);
        break;
      case 'azure_keyvault':
        pick(['vault_url', 'tenant_id', 'client_id', 'client_secret']);
        break;
      case 'adcs':
        pick(['agent_base_url', 'ca_server', 'ca_name', 'api_token', 'agent_id']);
        break;
      case 'acme':
        pick(['contact_email', 'domains', 'dns_provider_api_token', 'cloudflare_zone_id']);
        config.directory_url =
          values.directory_url === 'custom' ? values.custom_directory_url : values.directory_url;
        break;
    }
    createMutation.mutate({
      name: values.name,
      ca_type: values.ca_type,
      datacenter_id: values.datacenter_id || null,
      config,
    });
  };

  const dcOptions = (
    Array.isArray(datacenters)
      ? datacenters
      : datacenters?.datacenters || datacenters?.data || []
  ).map((dc: any) => ({ value: dc.id, label: `${dc.name} (${dc.code})` }));

  return (
    <Modal
      title="Add Certificate Authority"
      open={open}
      onOk={() => form.submit()}
      confirmLoading={createMutation.isPending}
      onCancel={onClose}
      okText="Create"
      width={560}
    >
      <Form
        form={form}
        layout="vertical"
        onFinish={handleFinish}
        initialValues={{ ca_type: 'aws_acm' }}
      >
        <Form.Item
          name="name"
          label="Name"
          rules={[{ required: true, message: 'Name is required' }]}
        >
          <Input placeholder="e.g. Production AWS ACM" autoFocus />
        </Form.Item>
        <Form.Item
          name="ca_type"
          label="Type"
          rules={[{ required: true }]}
        >
          <Select options={CA_TYPES} />
        </Form.Item>
        <Form.Item name="datacenter_id" label="Datacenter">
          <Select
            allowClear
            placeholder="Optional"
            loading={!datacenters}
            options={dcOptions}
          />
        </Form.Item>

        <Form.Item noStyle shouldUpdate={(prev, cur) => prev.ca_type !== cur.ca_type}>
          {({ getFieldValue }) => {
            const type = getFieldValue('ca_type');
            if (type === 'aws_acm') {
              return (
                <>
                  <Form.Item name="account_id" label="AWS Account ID">
                    <Input placeholder="e.g. 123456789012" />
                  </Form.Item>
                  <Form.Item name="regions" label="Regions">
                    <Select mode="tags" placeholder="us-east-1 (press Enter to add more)" open={false} suffixIcon={null} />
                  </Form.Item>
                  <Form.Item name="role_arn" label="Role ARN (optional)" tooltip="Cross-account role the platform assumes">
                    <Input placeholder="arn:aws:iam::123456789012:role/CertManagerScan" />
                  </Form.Item>
                  <Form.Item name="external_id" label="External ID (optional)">
                    <Input placeholder="External ID expected by the role's trust policy" />
                  </Form.Item>
                  <Form.Item name="profile_name" label="Profile Name (optional)">
                    <Input placeholder="AWS CLI profile — leave blank for default credential chain" />
                  </Form.Item>
                </>
              );
            }
            if (type === 'azure_keyvault') {
              return (
                <>
                  <Form.Item name="vault_url" label="Vault URL"
                    rules={[{ required: true, message: 'Vault URL is required' }]}>
                    <Input placeholder="https://myvault.vault.azure.net/" />
                  </Form.Item>
                  <Form.Item name="tenant_id" label="Tenant ID (optional)">
                    <Input placeholder="Azure AD tenant — blank uses DefaultAzureCredential" />
                  </Form.Item>
                  <Form.Item name="client_id" label="Client ID (optional)">
                    <Input placeholder="App registration client id" />
                  </Form.Item>
                  <Form.Item name="client_secret" label="Client Secret (optional)">
                    <Input.Password placeholder="App registration secret (encrypted at rest)" />
                  </Form.Item>
                </>
              );
            }
            if (type === 'adcs') {
              return (
                <>
                  <Form.Item name="agent_base_url" label="Agent Base URL">
                    <Input placeholder="https://agent-host:8443" />
                  </Form.Item>
                  <Form.Item name="agent_id" label="Agent ID (optional)">
                    <Input placeholder="Datacenter agent UUID" />
                  </Form.Item>
                  <Form.Item name="ca_server" label="CA Server">
                    <Input placeholder="e.g. ca01.corp.internal" />
                  </Form.Item>
                  <Form.Item name="ca_name" label="CA Name">
                    <Input placeholder="e.g. CORP-ROOT-CA" />
                  </Form.Item>
                  <Form.Item name="api_token" label="Agent API Token (optional)">
                    <Input.Password placeholder="Permanent agent token (encrypted at rest)" />
                  </Form.Item>
                </>
              );
            }
            if (type === 'acme') {
              return (
                <>
                  <Form.Item name="contact_email" label="Contact Email"
                    rules={[{ required: true, type: 'email', message: 'A contact email is required' }]}>
                    <Input placeholder="admin@example.com" />
                  </Form.Item>
                  <Form.Item name="domains" label="Domains"
                    tooltip="ACME has no 'list everything' API — list every domain this CA entry manages"
                    rules={[{ required: true, message: 'At least one domain is required' }]}>
                    <Select mode="tags" placeholder="example.com (press Enter to add more)" open={false} suffixIcon={null} />
                  </Form.Item>
                  <Form.Item name="directory_url" label="Directory" initialValue={ACME_DIRECTORIES[1].value}>
                    <Select options={ACME_DIRECTORIES} />
                  </Form.Item>
                  <Form.Item noStyle shouldUpdate={(prev, cur) => prev.directory_url !== cur.directory_url}>
                    {({ getFieldValue: getField2 }) =>
                      getField2('directory_url') === 'custom' ? (
                        <Form.Item name="custom_directory_url" label="Custom Directory URL"
                          rules={[{ required: true, message: 'Directory URL is required' }]}>
                          <Input placeholder="https://your-acme-server.example/directory" />
                        </Form.Item>
                      ) : null
                    }
                  </Form.Item>
                  <Form.Item name="dns_provider_api_token" label="Cloudflare API Token"
                    tooltip="Needs Zone:DNS:Edit permission on the zone(s) covering the domains above"
                    rules={[{ required: true, message: 'A Cloudflare API token is required for DNS-01' }]}>
                    <Input.Password placeholder="Cloudflare API token (encrypted at rest)" />
                  </Form.Item>
                  <Form.Item name="cloudflare_zone_id" label="Cloudflare Zone ID (optional)"
                    tooltip="Leave blank to resolve automatically from the domain">
                    <Input placeholder="Resolved automatically if omitted" />
                  </Form.Item>
                </>
              );
            }
            return null;
          }}
        </Form.Item>
      </Form>
    </Modal>
  );
}
