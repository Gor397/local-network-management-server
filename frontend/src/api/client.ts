export let csrf = '';
export function setCsrf(value:string) { csrf=value; }
export type FieldError={field:string|null;code:string;fix?:any;value?:string};
export class ApiError extends Error {constructor(public code:string,public status:number,public fields:FieldError[]=[]){super(code);}}
export async function api<T=any>(path:string, method='GET', body?:unknown):Promise<T> {
  const response = await fetch('/api/v1'+path,{method,credentials:'same-origin',headers:{...(body instanceof Blob?{'Content-Type':'application/octet-stream'}:{'Content-Type':'application/json'}),...(csrf?{'X-CSRF-Token':csrf}:{})},body:body===undefined?undefined:body instanceof Blob?body:JSON.stringify(body)});
  if(!response.ok){const result=await response.json().catch(()=>({}));throw new ApiError(result.error?.code||'request.failed',response.status,Array.isArray(result.error?.fields)?result.error.fields.filter((f:any)=>typeof f==='object'):[]);}
  if(response.status===204)return undefined as T;
  return response.json();
}
