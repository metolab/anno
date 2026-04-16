import { Layout, Menu, Button, theme } from "antd";
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
  const { signOut } = useAuth();
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
          <Button
            type="text"
            icon={<LogoutOutlined />}
            onClick={signOut}
          >
            退出登录
          </Button>
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
