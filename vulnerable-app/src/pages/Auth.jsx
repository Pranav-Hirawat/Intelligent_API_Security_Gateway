import { useState } from 'react'
import { Link, useNavigate, useLocation } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import toast from 'react-hot-toast'
import './Auth.css'

export default function Auth() {
  const location = useLocation()
  const isRegister = location.pathname === '/register'
  const navigate = useNavigate()
  const { login, register } = useAuth()

  const [form, setForm] = useState({ name: '', email: '', password: '', confirm: '' })
  const [loading, setLoading] = useState(false)
  const [errors, setErrors] = useState({})

  const set = (field, val) => {
    setForm((f) => ({ ...f, [field]: val }))
    setErrors((e) => ({ ...e, [field]: '' }))
  }

  const validate = () => {
    const e = {}
    if (isRegister && !form.name.trim()) e.name = 'Name is required'
    if (form.password.length < 6) e.password = 'Password must be at least 6 characters'
    if (isRegister && form.password !== form.confirm) e.confirm = 'Passwords do not match'
    setErrors(e)
    return Object.keys(e).length === 0
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!validate()) return
    setLoading(true)
    try {
      if (isRegister) {
        await register(form.name, form.email, form.password)
        toast.success('Account created! Welcome.')
      } else {
        await login(form.email, form.password)
        toast.success('Welcome back!')
      }
      const from = location.state?.from || '/'
      navigate(from)
    } catch (err) {
      toast.error(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="auth-header">
          <Link to="/" className="auth-logo">⬡ ShopForge</Link>
          <h1>{isRegister ? 'Create your account' : 'Sign in to ShopForge'}</h1>
          <p>{isRegister ? 'Already have an account?' : "Don't have an account?"}{' '}
            <Link to={isRegister ? '/login' : '/register'} className="auth-switch">
              {isRegister ? 'Sign in' : 'Create one'}
            </Link>
          </p>
        </div>

        <form onSubmit={handleSubmit} className="auth-form" noValidate>
          {isRegister && (
            <div className="form-group">
              <label className="form-label">Full Name</label>
              <input
                type="text"
                className={`form-input ${errors.name ? 'error' : ''}`}
                placeholder="Jane Smith"
                value={form.name}
                onChange={(e) => set('name', e.target.value)}
                autoComplete="name"
              />
              {errors.name && <span className="form-error">{errors.name}</span>}
            </div>
          )}

          <div className="form-group">
            <label className="form-label">Email Address</label>
            <input
              type="text"
              className={`form-input ${errors.email ? 'error' : ''}`}
              placeholder="you@example.com"
              value={form.email}
              onChange={(e) => set('email', e.target.value)}
              autoComplete="email"
            />
            {errors.email && <span className="form-error">{errors.email}</span>}
          </div>

          <div className="form-group">
            <label className="form-label">Password</label>
            <input
              type="password"
              className={`form-input ${errors.password ? 'error' : ''}`}
              placeholder={isRegister ? 'At least 6 characters' : '••••••••'}
              value={form.password}
              onChange={(e) => set('password', e.target.value)}
              autoComplete={isRegister ? 'new-password' : 'current-password'}
            />
            {errors.password && <span className="form-error">{errors.password}</span>}
          </div>

          {isRegister && (
            <div className="form-group">
              <label className="form-label">Confirm Password</label>
              <input
                type="password"
                className={`form-input ${errors.confirm ? 'error' : ''}`}
                placeholder="Repeat password"
                value={form.confirm}
                onChange={(e) => set('confirm', e.target.value)}
                autoComplete="new-password"
              />
              {errors.confirm && <span className="form-error">{errors.confirm}</span>}
            </div>
          )}

          <button type="submit" className="btn btn-primary btn-full btn-lg" disabled={loading}>
            {loading
              ? <><span className="spinner" /> {isRegister ? 'Creating Account…' : 'Signing In…'}</>
              : isRegister ? 'Create Account' : 'Sign In'
            }
          </button>
        </form>
      </div>
    </div>
  )
}
