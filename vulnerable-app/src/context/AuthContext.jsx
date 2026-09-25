import { createContext, useContext, useEffect, useState } from 'react'
import toast from 'react-hot-toast'
import api, { userApi, SESSION_EXPIRED_EVENT } from '../services/api'

const AuthContext = createContext(null)

// A real login's token is a signed JWT: three dot-separated segments. The
// storefront's old mock login stored a bare base64 id instead (see
// services/api.js history) -- one segment, no dots. A leftover one of those
// is not a live session; treating it as one is what sent a real fetch to
// /api/orders with no usable Authorization header and surfaced as "Could not
// reach the API" instead of a login screen.
const looksLikeAJwt = (token) => typeof token === 'string' && token.split('.').length === 3

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    const token = localStorage.getItem('sf_token')
    const stored = localStorage.getItem('sf_user')
    if (!token || !stored) return null
    if (!looksLikeAJwt(token)) {
      localStorage.removeItem('sf_token')
      localStorage.removeItem('sf_user')
      return null
    }
    try {
      return JSON.parse(stored)
    } catch {
      return null
    }
  })
  const loading = false

  // A real order call refused with 401 (an expired or otherwise dead token)
  // clears storage itself; this just brings the signed-in state in the UI
  // back in line with that, wherever the request happened to be made.
  useEffect(() => {
    const onExpired = () => {
      setUser(null)
      toast.error('Session expired, sign in again')
    }
    window.addEventListener(SESSION_EXPIRED_EVENT, onExpired)
    return () => window.removeEventListener(SESSION_EXPIRED_EVENT, onExpired)
  }, [])

  // Support both named and default export shapes for API clients.
  const authApi = (userApi && typeof userApi.login === 'function') ? userApi : api?.userApi

  const login = async (email, password) => {
    if (!authApi || typeof authApi.login !== 'function') {
      throw new Error('Auth API is not configured correctly')
    }
    const data = await authApi.login({ email, password })
    localStorage.setItem('sf_token', data.token)
    localStorage.setItem('sf_user', JSON.stringify(data.user))
    setUser(data.user)
    return data.user
  }

  const register = async (name, email, password) => {
    if (!authApi || typeof authApi.register !== 'function') {
      throw new Error('Auth API is not configured correctly')
    }
    const data = await authApi.register({ name, email, password })
    localStorage.setItem('sf_token', data.token)
    localStorage.setItem('sf_user', JSON.stringify(data.user))
    setUser(data.user)
    return data.user
  }

  const logout = () => {
    localStorage.removeItem('sf_token')
    localStorage.removeItem('sf_user')
    setUser(null)
  }

  const updateUser = (updated) => {
    localStorage.setItem('sf_user', JSON.stringify(updated))
    setUser(updated)
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout, updateUser }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)
