import { useState } from 'react';
import { Modal, Form, Input, Select, message } from 'antd';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import apiClient, { getEnveloped } from '../api/client';

const CA_TYPES = [
  { value: 'aws_acm', label: 'AWS ACM' },
  { value: 'azure_keyvault', label: 'Azure Key Vault' },
  { value: 'adcs', label: 'Active Directory CS' },
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
  const [jsonError, setJsonError] = useState<string | null>(null);

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

  const handleFinish = (values: any) => {
    let config: Record<string, unknown> | undefined;
    if (values.config_json && values.config_json.trim()) {
      try {
        config = JSON.parse(values.config_json);
      } catch {
        setJsonError('Config must be valid JSON');
        return;
      }
    }
    createMutation.mutate({
      name: values.name,
      ca_type: values.ca_type,
      datacenter_id: values.datacenter_id || null,
      config,
    });
  };

  return (
    <Modal
      title="Add Certificate Authority"
      open={open}
      onOk={() => form.submit()}
      confirmLoading={createMutation.isPending}
      onCancel={onClose}
      okText="Create"
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
            options={(
              Array.isArray(datacenters)
                ? datacenters
                : datacenters?.datacenters || datacenters?.data || []
            ).map((dc: any) => ({ value: dc.id, label: `${dc.name} (${dc.code})` }))}
          />
        </Form.Item>
        <Form.Item
          name="config_json"
          label="Config JSON"
          tooltip="Provider-specific settings, e.g. AWS account/region, Azure vault URL. Secrets are encrypted at rest."
          validateStatus={jsonError ? 'error' : undefined}
          help={jsonError || undefined}
        >
          <Input.TextArea
            rows={4}
            placeholder='{"account_id": "123456789012", "regions": ["us-east-1"]}'
            onChange={() => setJsonError(null)}
          />
        </Form.Item>
      </Form>
    </Modal>
  );
}
