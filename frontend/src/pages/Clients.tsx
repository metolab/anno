import {
  App,
  Button,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Table,
  Tabs,
  Tag,
  Tooltip,
  Typography,
} from "antd";
import {
  CopyOutlined,
  DeleteOutlined,
  KeyOutlined,
  PlusOutlined,
  ReloadOutlined,
} from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  addMapping,
  createRegistryEntry,
  deleteClient,
  deleteMapping,
  deleteRegistryEntry,
  fetchClients,
  fetchRegistry,
  regenerateRegistryKey,
  updateRegistryEntry,
  type ClientDto,
  type MappingDto,
  type RegistryEntryDto,
} from "../api/client";

// ============================================================================
// Connected Clients Tab
// ============================================================================

function ConnectedClientsTab() {
  const { message } = App.useApp();
  const [clients, setClients] = useState<ClientDto[]>([]);
  const [loading, setLoading] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const [modalClientId, setModalClientId] = useState<number | null>(null);
  const [form] = Form.useForm();

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      setClients(await fetchClients());
    } catch {
      message.error("Failed to load clients");
    } finally {
      setLoading(false);
    }
  }, [message]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const openAdd = (clientId: number) => {
    setModalClientId(clientId);
    form.resetFields();
    form.setFieldsValue({ protocol: "tcp" });
    setModalOpen(true);
  };

  const submitMapping = async () => {
    if (modalClientId == null) return;
    const v = await form.validateFields();
    try {
      await addMapping(modalClientId, {
        server_port: v.server_port,
        protocol: v.protocol,
        target_host: v.target_host,
        target_port: v.target_port,
      });
      message.success("Mapping added");
      setModalOpen(false);
      await reload();
    } catch {
      message.error("Failed to add mapping");
    }
  };

  const columns: ColumnsType<ClientDto> = useMemo(
    () => [
      { title: "ID", dataIndex: "id", width: 90 },
      { title: "Name", dataIndex: "name" },
      {
        title: "Status",
        dataIndex: "status",
        render: (s: string) =>
          s === "online" ? <Tag color="green">online</Tag> : <Tag>offline</Tag>,
      },
      { title: "Remote", dataIndex: "remote_addr" },
      {
        title: "HTTP proxy (local)",
        dataIndex: "http_proxy_port",
        render: (p?: number | null) => (p ? `127.0.0.1:${p}` : "-"),
      },
      {
        title: "Actions",
        key: "actions",
        render: (_, row) => (
          <Space>
            <Button size="small" onClick={() => openAdd(row.id)}>
              Add mapping
            </Button>
            <Button
              size="small"
              danger
              onClick={() => {
                Modal.confirm({
                  title: "Delete client?",
                  onOk: async () => {
                    try {
                      await deleteClient(row.id);
                      message.success("Deleted");
                      await reload();
                    } catch {
                      message.error("Delete failed");
                    }
                  },
                });
              }}
            >
              Delete
            </Button>
          </Space>
        ),
      },
    ],
    [reload],
  );

  const expandedRowRender = (row: ClientDto) => {
    const mc: ColumnsType<MappingDto> = [
      { title: "Server port", dataIndex: "server_port", width: 120 },
      { title: "Protocol", dataIndex: "protocol", width: 100 },
      { title: "Target", dataIndex: "target" },
      {
        title: "Action",
        key: "a",
        width: 120,
        render: (_, m) => (
          <Button
            size="small"
            danger
            onClick={async () => {
              try {
                await deleteMapping(row.id, m.server_port);
                message.success("Mapping removed");
                await reload();
              } catch {
                message.error("Failed to remove mapping");
              }
            }}
          >
            Remove
          </Button>
        ),
      },
    ];
    return (
      <Table<MappingDto>
        size="small"
        rowKey={(m) => `${m.server_port}-${m.protocol}`}
        columns={mc}
        dataSource={row.mappings}
        pagination={false}
      />
    );
  };

  return (
    <>
      <Space style={{ marginBottom: 16 }}>
        <Button icon={<ReloadOutlined />} onClick={() => reload()} loading={loading}>
          刷新
        </Button>
      </Space>

      <Table<ClientDto>
        rowKey="id"
        loading={loading}
        columns={columns}
        dataSource={clients}
        expandable={{ expandedRowRender }}
      />

      <Modal
        title="Add port mapping"
        open={modalOpen}
        onCancel={() => setModalOpen(false)}
        onOk={submitMapping}
        destroyOnClose
      >
        <Form form={form} layout="vertical">
          <Form.Item
            name="server_port"
            label="Server port"
            rules={[{ required: true }]}
          >
            <InputNumber min={1} max={65535} style={{ width: "100%" }} />
          </Form.Item>
          <Form.Item name="protocol" label="Protocol" rules={[{ required: true }]}>
            <Select
              options={[
                { value: "tcp", label: "tcp" },
                { value: "udp", label: "udp" },
                { value: "both", label: "both" },
              ]}
            />
          </Form.Item>
          <Form.Item
            name="target_host"
            label="Target host"
            rules={[{ required: true }]}
          >
            <Input placeholder="192.168.1.10 or example.com" />
          </Form.Item>
          <Form.Item
            name="target_port"
            label="Target port"
            rules={[{ required: true }]}
          >
            <InputNumber min={1} max={65535} style={{ width: "100%" }} />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
}

// ============================================================================
// Client Registry Tab
// ============================================================================

function ClientRegistryTab() {
  const { message, modal } = App.useApp();
  const [entries, setEntries] = useState<RegistryEntryDto[]>([]);
  const [loading, setLoading] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [editEntry, setEditEntry] = useState<RegistryEntryDto | null>(null);
  const [form] = Form.useForm();
  const [editForm] = Form.useForm();

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      setEntries(await fetchRegistry());
    } catch {
      message.error("Failed to load registry");
    } finally {
      setLoading(false);
    }
  }, [message]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const handleCreate = async () => {
    const v = await form.validateFields();
    try {
      await createRegistryEntry({ name: v.name, description: v.description || undefined });
      message.success("客户端条目已创建");
      setCreateOpen(false);
      form.resetFields();
      await reload();
    } catch (e: unknown) {
      const err = e as { response?: { data?: { message?: string } } };
      message.error(err.response?.data?.message ?? "创建失败");
    }
  };

  const handleEdit = async () => {
    if (!editEntry) return;
    const v = await editForm.validateFields();
    try {
      await updateRegistryEntry(editEntry.name, { description: v.description || null });
      message.success("已更新");
      setEditEntry(null);
      await reload();
    } catch {
      message.error("更新失败");
    }
  };

  const handleDelete = (name: string) => {
    modal.confirm({
      title: `删除客户端 "${name}"？`,
      content: "此操作不可撤销，客户端将无法再使用当前key连接。",
      okType: "danger",
      onOk: async () => {
        try {
          await deleteRegistryEntry(name);
          message.success("已删除");
          await reload();
        } catch {
          message.error("删除失败");
        }
      },
    });
  };

  const handleRegenKey = (name: string) => {
    modal.confirm({
      title: `重新生成 "${name}" 的 Key？`,
      content: "旧 key 将立即失效，客户端需要使用新 key 重连。",
      okType: "danger",
      onOk: async () => {
        try {
          const updated = await regenerateRegistryKey(name);
          message.success("Key 已更新");
          setEntries((prev) => prev.map((e) => (e.name === name ? updated : e)));
        } catch {
          message.error("操作失败");
        }
      },
    });
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text).then(
      () => message.success("已复制到剪贴板"),
      () => message.error("复制失败"),
    );
  };

  const columns: ColumnsType<RegistryEntryDto> = [
    {
      title: "名称",
      dataIndex: "name",
      width: 160,
    },
    {
      title: "Key",
      dataIndex: "key",
      render: (key: string) => (
        <Space>
          <Typography.Text code style={{ fontSize: 12 }}>
            {key}
          </Typography.Text>
          <Tooltip title="复制">
            <Button
              type="text"
              size="small"
              icon={<CopyOutlined />}
              onClick={() => copyToClipboard(key)}
            />
          </Tooltip>
        </Space>
      ),
    },
    {
      title: "描述",
      dataIndex: "description",
      render: (v?: string | null) => v ?? "-",
    },
    {
      title: "创建时间",
      dataIndex: "created_at",
      width: 180,
      render: (ts: number) => new Date(ts * 1000).toLocaleString(),
    },
    {
      title: "操作",
      key: "actions",
      width: 200,
      render: (_, row) => (
        <Space>
          <Tooltip title="编辑描述">
            <Button
              size="small"
              onClick={() => {
                setEditEntry(row);
                editForm.setFieldsValue({ description: row.description });
              }}
            >
              编辑
            </Button>
          </Tooltip>
          <Tooltip title="重新生成 Key">
            <Button
              size="small"
              icon={<KeyOutlined />}
              onClick={() => handleRegenKey(row.name)}
            />
          </Tooltip>
          <Tooltip title="删除">
            <Button
              size="small"
              danger
              icon={<DeleteOutlined />}
              onClick={() => handleDelete(row.name)}
            />
          </Tooltip>
        </Space>
      ),
    },
  ];

  return (
    <>
      <Space style={{ marginBottom: 16 }}>
        <Button
          type="primary"
          icon={<PlusOutlined />}
          onClick={() => {
            form.resetFields();
            setCreateOpen(true);
          }}
        >
          新建客户端
        </Button>
        <Button icon={<ReloadOutlined />} onClick={() => reload()} loading={loading}>
          刷新
        </Button>
      </Space>

      <Table<RegistryEntryDto>
        rowKey="name"
        loading={loading}
        columns={columns}
        dataSource={entries}
        pagination={false}
      />

      <Modal
        title="新建客户端条目"
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
        onOk={handleCreate}
        destroyOnClose
      >
        <Form form={form} layout="vertical">
          <Form.Item
            name="name"
            label="客户端名称"
            rules={[
              { required: true, message: "请输入名称" },
              { pattern: /^[a-zA-Z0-9_-]+$/, message: "只允许字母、数字、- 和 _" },
            ]}
          >
            <Input placeholder="my-client" />
          </Form.Item>
          <Form.Item name="description" label="描述（可选）">
            <Input placeholder="描述信息" />
          </Form.Item>
        </Form>
        <Typography.Text type="secondary">
          Key 将在创建后自动生成。
        </Typography.Text>
      </Modal>

      <Modal
        title="编辑客户端条目"
        open={!!editEntry}
        onCancel={() => setEditEntry(null)}
        onOk={handleEdit}
        destroyOnClose
      >
        <Form form={editForm} layout="vertical">
          <Form.Item name="description" label="描述">
            <Input placeholder="描述信息" />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
}

// ============================================================================
// Page
// ============================================================================

export default function ClientsPage() {
  return (
    <div>
      <Typography.Title level={3} style={{ marginTop: 0, marginBottom: 16 }}>
        客户端管理
      </Typography.Title>
      <Tabs
        items={[
          {
            key: "online",
            label: "在线客户端",
            children: <ConnectedClientsTab />,
          },
          {
            key: "registry",
            label: "客户端注册表",
            children: <ClientRegistryTab />,
          },
        ]}
      />
    </div>
  );
}
