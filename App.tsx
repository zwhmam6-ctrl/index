import { Navigate, Route, Routes } from 'react-router-dom'
import Layout from './components/Layout'
import ProtectedRoute from './components/ProtectedRoute'
import Landing from './pages/Landing'
import Login from './pages/Login'
import Register from './pages/Register'
import ForgotPassword from './pages/ForgotPassword'
import ResetPassword from './pages/ResetPassword'
import Home from './pages/Home'
import Profile from './pages/Profile'
import EditProfile from './pages/EditProfile'
import Bookmarks from './pages/Bookmarks'
import PostPage from './pages/PostPage'
import Notifications from './pages/Notifications'
import Explore from './pages/Explore'
import Messages from './pages/Messages'
import Settings from './pages/Settings'
import Admin from './pages/Admin'
import Legal from './pages/Legal'
import NotFound from './pages/NotFound'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/forgot-password" element={<ForgotPassword />} />
      <Route path="/reset-password" element={<ResetPassword />} />
      {["/privacy", "/terms", "/guidelines", "/help"].map((p) => <Route key={p} path={p} element={<Legal />} />)}
      <Route element={<ProtectedRoute />}>
        <Route element={<Layout />}>
          <Route path="/home" element={<Home />} />
          <Route path="/bookmarks" element={<Bookmarks />} />
          <Route path="/post/:id" element={<PostPage />} />
          <Route path="/notifications" element={<Notifications />} />
          <Route path="/u/:username" element={<Profile />} />
          <Route path="/settings/profile" element={<EditProfile />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/explore" element={<Explore />} />
          <Route path="/messages" element={<Messages />} />
          <Route path="/admin" element={<Admin />} />
        </Route>
      </Route>
      <Route path="*" element={<NotFound />} />
    </Routes>
  )
}
