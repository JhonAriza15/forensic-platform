import Sidebar from './Sidebar'

export default function Layout({ children }) {
  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: '#0b1120' }}>
      <Sidebar />
      <main style={{
        marginLeft: '220px',
        flex: 1,
        padding: '2rem',
        color: '#f1f5f9',
        minHeight: '100vh'
      }}>
        {children}
      </main>
    </div>
  )
}