import {useEffect,useState,useCallback} from 'react';
import {api} from '../api/client';
export function useData<T=any>(path:string, revision=0) {
  const [data,setData]=useState<T|null>(null),[error,setError]=useState(''),[loading,setLoading]=useState(true);
  const reload=useCallback(()=>{setLoading(true);api<T>(path).then(d=>{setData(d);setError('');}).catch(e=>setError(e.code||'request.failed')).finally(()=>setLoading(false));},[path]);
  useEffect(()=>{reload();},[reload,revision]);
  return {data,error,loading,reload};
}
