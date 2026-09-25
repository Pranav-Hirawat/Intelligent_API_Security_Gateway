/**
 * api.js — Mock API layer
 *
 * Mirrors the real REST API surface exactly.
 * Swap this file for the real axios version when a backend is ready.
 * Real backend endpoints are documented in comments next to each function.
 */

import { MOCK_PRODUCTS, MOCK_USERS, MOCK_ORDERS } from './mockData'

// ─── In-memory state (simulates a database) ───────────────────────────────────
let products = MOCK_PRODUCTS.map((p) => ({ ...p }))
let users = MOCK_USERS.map((u) => ({ ...u }))
// The admin panel's mock order list only. Real orders (orderApi below) live in
// the backend's database, not here -- see orderApi's comment.
let orders = MOCK_ORDERS.map((o) => ({ ...o }))

// ─── Helpers ──────────────────────────────────────────────────────────────────
const delay = (ms = 350) => new Promise((r) => setTimeout(r, ms))

const ENV_API_MODE = (import.meta.env.VITE_API_MODE || 'backend').toLowerCase()
const BACKEND_API_URL = import.meta.env.VITE_BACKEND_API_URL || 'http://localhost:5002'
const GATEWAY_API_URL = import.meta.env.VITE_GATEWAY_API_URL || 'http://localhost:8082'

// Which URL orders and login are sent to. Read fresh on every call instead of
// once at import time, so the switch in the navbar takes effect immediately.
export const getApiMode = () => {
  const stored = localStorage.getItem('api_mode')
  return (stored || ENV_API_MODE) === 'gateway' ? 'gateway' : 'backend'
}

// Sets the mode and tells anything watching (the navbar switch, an open order
// page that should refetch) that it changed.
export const setApiMode = (mode) => {
  localStorage.setItem('api_mode', mode === 'gateway' ? 'gateway' : 'backend')
  window.dispatchEvent(new CustomEvent(API_MODE_EVENT))
}

export const API_MODE_EVENT = 'sf:api-mode'
export const SESSION_EXPIRED_EVENT = 'sf:session-expired'

const getApiBaseUrl = () => {
  const mode = getApiMode()
  return mode === 'gateway'
    ? GATEWAY_API_URL
    : BACKEND_API_URL
}

const err = (msg, status = 400) => {
  const e = new Error(msg)
  e.status = status
  throw e
}

// The logged-in user, for the wishlist/reviews mock data that never left the
// browser. sf_user is what a real API login stored; this looks it up (or
// adopts it) by email so wishlist and reviews keep working for an account
// that has no mock record.
const getCurrentUser = () => {
  const stored = localStorage.getItem('sf_user')
  if (!stored) return null
  let saved
  try {
    saved = JSON.parse(stored)
  } catch { return null }
  if (!saved?.email) return null

  const known = users.find((u) => u.email === saved.email)
  if (known) return known

  const adopted = { ...saved, wishlist: saved.wishlist || [] }
  users.push(adopted)
  return adopted
}

const makeToken = (id) => btoa(String(id))

// Shapes a signed-in user from the real backend into what the storefront
// reads everywhere else (Navbar's user.name/isAdmin, getCurrentUser's email
// lookup above).
const normalizeBackendUser = (rawUser) => ({
  _id: String(rawUser.id ?? rawUser._id),
  id: rawUser.id,
  name: rawUser.name || rawUser.email,
  email: rawUser.email,
  role: rawUser.role,
  isAdmin: rawUser.role === 'administrator',
  wishlist: [],
})

// Real calls (orders) go through here: the caller's token, and one place that
// decides what an expired token or a gateway refusal means, instead of that
// being repeated in every orderApi method.
async function apiFetch(path, { method = 'GET', body } = {}) {
  const token = localStorage.getItem('sf_token')
  const headers = { 'Content-Type': 'application/json' }
  if (token) headers.Authorization = `Bearer ${token}`

  let res
  try {
    res = await fetch(`${getApiBaseUrl()}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    })
  } catch {
    err('Could not reach the API. Is the stack running?', 0)
  }

  if (res.status === 401) {
    localStorage.removeItem('sf_token')
    localStorage.removeItem('sf_user')
    window.dispatchEvent(new CustomEvent(SESSION_EXPIRED_EVENT))
    err('Your session has expired. Sign in again.', 401)
  }
  if (res.status === 429) {
    err('Blocked by the gateway: too many requests. Wait a moment and try again.', 429)
  }
  if (res.status === 403) {
    err('Blocked by the gateway.', 403)
  }

  const text = await res.text()
  let data = null
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      err('The API returned something that was not JSON', res.status)
    }
  }
  if (!res.ok) {
    err(data?.message || `Request failed: ${res.status}`, res.status)
  }
  return data
}

// ─── Product API ──────────────────────────────────────────────────────────────
// Real: GET /api/products
export const productApi = {
  // Fetches the whole catalogue from the real backend (GET /api/products),
  // through the gateway or straight to the API depending on the API mode. This
  // is the one product call that leaves the browser; the rest below are still
  // the in-memory mock. If the backend is unreachable it falls back to the mock
  // so browsing the catalogue still works offline.
  getAllProducts: async (params = {}) => {
    const qs = new URLSearchParams()
    if (params.category) qs.set('category', params.category)
    if (params.search) qs.set('search', params.search)
    const suffix = qs.toString() ? `?${qs}` : ''

    try {
      const res = await fetch(`${getApiBaseUrl()}/api/products${suffix}`)
      if (!res.ok) throw new Error(`products request failed: ${res.status}`)
      const data = await res.json()
      return { products: data.products || [], total: data.total ?? (data.products || []).length }
    } catch {
      // Offline fallback: the same local list the mock getAll works from.
      let result = [...products]
      if (params.category) result = result.filter((p) => p.category === params.category)
      if (params.search) {
        const q = params.search.toLowerCase()
        result = result.filter((p) => p.name.toLowerCase().includes(q))
      }
      return { products: result, total: result.length }
    }
  },

  getAll: async (params = {}) => {
    await delay()
    let result = [...products]

    if (params.category) result = result.filter((p) => p.category === params.category)
    if (params.featured === true || params.featured === 'true') result = result.filter((p) => p.isFeatured)
    if (params.newArrival === true || params.newArrival === 'true') result = result.filter((p) => p.isNewArrival)
    if (params.search) {
      const q = params.search.toLowerCase()
      result = result.filter((p) =>
        p.name.toLowerCase().includes(q) ||
        p.description.toLowerCase().includes(q) ||
        p.tags?.some((t) => t.toLowerCase().includes(q))
      )
    }
    if (params.minPrice) result = result.filter((p) => p.price >= parseFloat(params.minPrice))
    if (params.maxPrice) result = result.filter((p) => p.price <= parseFloat(params.maxPrice))
    if (params.rating) result = result.filter((p) => p.rating >= parseFloat(params.rating))

    switch (params.sort) {
      case 'price_asc': result.sort((a, b) => a.price - b.price); break
      case 'price_desc': result.sort((a, b) => b.price - a.price); break
      case 'rating': result.sort((a, b) => b.rating - a.rating); break
      default: result.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    }

    const page = parseInt(params.page) || 1
    const limit = parseInt(params.limit) || 12
    const total = result.length
    const paginated = result.slice((page - 1) * limit, page * limit)

    return { products: paginated, page, pages: Math.ceil(total / limit), total }
  },

  // Real: GET /api/products/:id
  getById: async (id) => {
    await delay()
    const p = products.find((p) => p._id === id)
    if (!p) err('Product not found', 404)
    return { ...p }
  },

  // Real: GET /api/products/categories
  getCategories: async () => {
    await delay(150)
    return [...new Set(products.map((p) => p.category))]
  },

  // Real: POST /api/products/:id/reviews
  addReview: async (id, { rating, comment }) => {
    await delay()
    const user = getCurrentUser()
    if (!user) err('Not authenticated', 401)
    const p = products.find((p) => p._id === id)
    if (!p) err('Product not found', 404)
    if (p.reviews?.some((r) => r._id.includes(user._id))) err('Already reviewed')
    const review = {
      _id: `r_${user._id}_${Date.now()}`,
      name: user.name,
      rating,
      comment,
      createdAt: new Date().toISOString(),
    }
    p.reviews = [...(p.reviews || []), review]
    p.numReviews = p.reviews.length
    p.rating = p.reviews.reduce((s, r) => s + r.rating, 0) / p.reviews.length
    return { message: 'Review added' }
  },
}

// ─── User API ─────────────────────────────────────────────────────────────────
export const userApi = {
  // Real: POST /api/users/register
  register: async ({ name, email }) => {
    await delay()
    if (users.find((u) => u.email === email)) err('Email already in use')
    // Client-side register is profile-only. Real auth is POST /api/login.
    const user = { _id: `u${Date.now()}`, name, email, isAdmin: false, wishlist: [] }
    users.push(user)
    return { user, token: makeToken(user._id) }
  },

  // Real: POST /api/login — passwords are checked only by the backend.
  login: async ({ email, password }) => {
    const BASE_URL = getApiBaseUrl()
    let res
    try {
      res = await fetch(`${BASE_URL}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      })
    } catch {
      // fetch() throwing here doesn't only mean "the API is down" -- a
      // refusal the gateway wrote itself and didn't (or couldn't) mark with
      // CORS for this origin looks identical to the browser: an opaque
      // network error.
      let reachable = true
      try {
        reachable = (await fetch(`${BASE_URL}/api/health`)).ok
      } catch {
        reachable = false
      }
      if (reachable) {
        throw new Error('The login request was blocked in a way the browser could not read the reason for.')
      }
      throw new Error('Could not reach the login API. Is the stack running?')
    }

    if (res.status === 403) {
      // The gateway's SQL injection detector, not a credentials problem.
      window.__ATTACK_BLOCKED__ = true
      throw new Error('🚨 SQL Injection Attack Blocked')
    }
    if (res.status === 429) {
      throw new Error('Too many attempts. Wait a moment and try again.')
    }

    const text = await res.text()
    let parsed = null
    try {
      parsed = text ? JSON.parse(text) : null
    } catch {
      throw new Error('Login endpoint returned invalid JSON')
    }

    if (!res.ok) {
      throw new Error(parsed?.message || 'Invalid email or password')
    }
    if (!parsed?.user || !parsed?.token) {
      throw new Error('Login endpoint returned an unsupported response shape')
    }

    return { user: normalizeBackendUser(parsed.user), token: parsed.token }
  },

  // Real: GET /api/users/profile
  getProfile: async () => {
    await delay(150)
    const user = getCurrentUser()
    if (!user) err('Not authenticated', 401)
    return user
  },

  // Real: PUT /api/users/profile
  updateProfile: async (data) => {
    await delay()
    const user = getCurrentUser()
    if (!user) err('Not authenticated', 401)
    if (data.name) user.name = data.name
    if (data.email) user.email = data.email
    return { user, token: makeToken(user._id) }
  },

  // Real: GET /api/users/wishlist
  getWishlist: async () => {
    await delay()
    const user = getCurrentUser()
    if (!user) err('Not authenticated', 401)
    return products.filter((p) => (user.wishlist || []).includes(p._id))
  },

  // Real: POST /api/users/wishlist/:productId
  toggleWishlist: async (productId) => {
    await delay(200)
    const user = getCurrentUser()
    if (!user) err('Not authenticated', 401)
    user.wishlist = user.wishlist || []
    const idx = user.wishlist.indexOf(productId)
    if (idx > -1) user.wishlist.splice(idx, 1)
    else user.wishlist.push(productId)
    return { wishlist: user.wishlist }
  },
}

// ─── Order API ────────────────────────────────────────────────────────────────
// Maps a backend order onto the shape the storefront pages already read.
// order.id is numeric on the backend (that's the id the BOLA walk counts
// through); _id here is just that number as a string, so the existing
// /orders/:id route and order._id.slice(...) keep working unchanged.
const toUiOrder = (order) => {
  const items = (order.items || []).map((item) => ({
    product: item.productId,
    name: item.name,
    image: item.image,
    price: Number(item.price),
    quantity: item.quantity,
  }))
  return {
    _id: String(order.id),
    orderNumber: order.orderNumber,
    customerName: order.customerName,
    items,
    shippingAddress: order.shippingAddress,
    subtotal: items.reduce((sum, item) => sum + item.price * item.quantity, 0),
    totalPrice: Number(order.total),
    status: order.status,
    createdAt: order.createdAt,
  }
}

export const orderApi = {
  // Real: POST /api/orders
  //
  // A real write to the backend's orders table, unlike the rest of this file
  // -- so a placed order is owned by the logged-in user and immediately shows
  // up in GET /api/orders, and is a real target for the BOLA route below.
  create: async ({ items, shippingAddress, paymentMethod }) => {
    const data = await apiFetch('/api/orders', {
      method: 'POST',
      body: {
        items: items.map((item) => ({
          productId: item.product,
          name: item.name,
          price: item.price,
          quantity: item.quantity,
          image: item.image,
        })),
        shippingAddress,
        paymentMethod,
      },
    })
    return toUiOrder(data.order)
  },

  // Real: GET /api/orders
  //
  // The caller's own orders, as read from the backend's database.
  getMyOrders: async () => {
    const data = await apiFetch('/api/orders')
    return (data.orders || []).map(toUiOrder)
  },

  // Real: GET /api/orders/:id
  //
  // Deliberately the vulnerable backend route (see vulnerable-app/backend's
  // routes/orders.js): in "Backend" mode this returns any order by id; in
  // "Gateway" mode the ownership check answers 404 for one that is not the
  // caller's. That difference, on the same URL, is the demo.
  getById: async (id) => {
    const data = await apiFetch(`/api/orders/${encodeURIComponent(id)}`)
    return toUiOrder(data.order)
  },
}

// ─── Admin API ────────────────────────────────────────────────────────────────
export const adminApi = {
  // Real: GET /api/admin/stats
  getStats: async () => {
    await delay()
    return {
      totalProducts: products.length,
      totalOrders: orders.length,
      totalUsers: users.length,
      totalRevenue: orders.reduce((s, o) => s + o.totalPrice, 0),
    }
  },

  // Real: POST /api/admin/product
  createProduct: async (data) => {
    await delay()
    const product = {
      ...data,
      _id: `p${Date.now()}`,
      rating: 0,
      numReviews: 0,
      reviews: [],
      createdAt: new Date().toISOString(),
    }
    products.unshift(product)
    return product
  },

  // Real: PUT /api/admin/product/:id
  updateProduct: async (id, data) => {
    await delay()
    const idx = products.findIndex((p) => p._id === id)
    if (idx === -1) err('Product not found', 404)
    products[idx] = { ...products[idx], ...data }
    return products[idx]
  },

  // Real: DELETE /api/admin/product/:id
  deleteProduct: async (id) => {
    await delay()
    const idx = products.findIndex((p) => p._id === id)
    if (idx === -1) err('Product not found', 404)
    products.splice(idx, 1)
    return { message: 'Product deleted' }
  },

  // Real: GET /api/admin/orders
  getOrders: async (params = {}) => {
    await delay()
    const page = parseInt(params.page) || 1
    const limit = 20
    const total = orders.length
    const paginated = orders.slice((page - 1) * limit, page * limit)
    return { orders: paginated, page, pages: Math.ceil(total / limit), total }
  },

  // Real: PUT /api/admin/orders/:id/status
  updateOrderStatus: async (id, status) => {
    await delay()
    const order = orders.find((o) => o._id === id)
    if (!order) err('Order not found', 404)
    order.status = status
    if (status === 'delivered') {
      order.isDelivered = true
      order.deliveredAt = new Date().toISOString()
    }
    return order
  },

  // Real: GET /api/admin/users
  getUsers: async () => {
    await delay()
    return users.map((user) => {
    const {  ...safeUser } = user;
    return safeUser;
  });
  },
}

export default { productApi, userApi, orderApi, adminApi }
