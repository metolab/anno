import { Layout, Menu, Button, theme, Spin, Result } from "antd";
import {
  CloudServerOutlined,
  DashboardOutlined,
  LogoutOutlined,
} from "@ant-design/icons";
import { Link, Navigate, Route, Routes, useLocation } from "react-router-dom";
import ClientsPage from "./pages/Clients";
import DashboardPage from "./pages/Dashboard";
import LoginPage from "./pages/Login";
import { useAuth } from "./contexts/AuthContext";

const { Header, Sider, Content } = Layout;

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth();
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" replace />;
}

function AdminLayout() {
  const location = useLocation();
  const { signOut, authMode } = useAuth();
  const {
    token: { colorBgContainer, borderRadiusLG },
  } = theme.useToken();

  return (
    <Layout style={{ minHeight: "100vh" }}>
      <Sider breakpoint="lg" collapsedWidth="0">
        <div
          style={{
            height: 64,
            margin: 16,
            color: "white",
            fontWeight: 700,
            fontSize: 16,
          }}
        >
          anno
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[location.pathname]}
          items={[
            {
              key: "/",
              icon: <DashboardOutlined />,
              label: <Link to="/">Dashboard</Link>,
            },
            {
              key: "/clients",
              icon: <CloudServerOutlined />,
              label: <Link to="/clients">Clients</Link>,
            },
          ]}
        />
      </Sider>
      <Layout>
        <Header
          style={{
            padding: "0 16px",
            background: colorBgContainer,
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <span style={{ fontSize: 16, fontWeight: 600 }}>anno</span>
          {authMode !== "none" && (
            <Button type="text" icon={<LogoutOutlined />} onClick={signOut}>
              退出登录
            </Button>
          )}
        </Header>
        <Content style={{ margin: 16 }}>
          <div
            style={{
              padding: 24,
              minHeight: 360,
              background: colorBgContainer,
              borderRadius: borderRadiusLG,
            }}
          >
            <Routes>
              <Route path="/" element={<DashboardPage />} />
              <Route path="/clients" element={<ClientsPage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </div>
        </Content>
      </Layout>
    </Layout>
  );
}

export default function App() {
  const { isReady, configError, reloadConfig } = useAuth();

  if (!isReady) {
    return (
      <div
        style={{
          display: "flex",
          minHeight: "100vh",
          alignItems: "center",
          justifyContent: "center",
          background: "#f0f2f5",
        }}
      >
        <Spin size="large" />
      </div>
    );
  }

  if (configError) {
    return (
      <div
        style={{
          display: "flex",
          minHeight: "100vh",
          alignItems: "center",
          justifyContent: "center",
          background: "#f0f2f5",
        }}
      >
        <Result
          status="error"
          title="无法加载认证配置"
          subTitle={configError}
          extra={
            <Button type="primary" onClick={() => void reloadConfig()}>
              重试
            </Button>
          }
        />
      </div>
    );
  }

  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/*"
        element={
          <RequireAuth>
            <AdminLayout />
          </RequireAuth>
        }
      />
    </Routes>
  );
}
