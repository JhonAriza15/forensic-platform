import { Routes, Route, Navigate } from 'react-router-dom'
import Login from './pages/Login'
import Register from './pages/Register'
import Dashboard from './pages/Dashboard'
import Layout from './components/Layout'
import Findings from './pages/Findings'
import VulnScanner from './pages/VulnScanner'






const PrivateRoute = ({ children }) => {
  const token = localStorage.getItem('token')
  return token ? <Layout>{children}</Layout> : <Navigate to="/login" />
}

function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/dashboard" element={
        <PrivateRoute>
          <Dashboard />
        </PrivateRoute>
      } />
      <Route path="/findings" element={
        <PrivateRoute>
          <Findings />
        </PrivateRoute>
      } />
      <Route path="/vuln-scanner" element={
        <PrivateRoute>
          <VulnScanner />
        </PrivateRoute>
      } />
      <Route path="/" element={<Navigate to="/dashboard" />} />
    </Routes>
  )
}


export default App

