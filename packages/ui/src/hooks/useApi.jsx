import { useState } from 'react'
import { useError } from '@/store/context/ErrorContext'

export default (apiFunc) => {
    const [data, setData] = useState(null)
    const [loading, setLoading] = useState(false)
    const [error, setApiError] = useState(null)
    const { setError, handleError } = useError()

    const request = async (...args) => {
        console.log('🌐 useApi - Starting request with args:', args)
        console.log('🌐 useApi - API function:', apiFunc.name || 'anonymous')
        setLoading(true)
        try {
            const result = await apiFunc(...args)
            console.log('✅ useApi - Request successful:', result)
            setData(result.data)
            setError(null)
            setApiError(null)
        } catch (err) {
            console.error('❌ useApi - Request failed:', err)
            console.error('❌ useApi - Error response:', err.response)
            handleError(err || 'Unexpected Error!')
            setApiError(err || 'Unexpected Error!')
        } finally {
            setLoading(false)
        }
    }

    return {
        error,
        data,
        loading,
        request
    }
}
