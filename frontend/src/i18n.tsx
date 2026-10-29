import {createContext,useContext} from 'react';
import en from './locales/en.json';
import hy from './locales/hy.json';
import ru from './locales/ru.json';
export type Language='en'|'hy'|'ru';
export const dictionaries:Record<Language,Record<string,string>>={en,hy,ru};
export const LocaleContext=createContext<{language:Language;setLanguage:(v:Language)=>void}>({language:'en',setLanguage:()=>{}});
export function useT(){const {language}=useContext(LocaleContext);return (key:string):string=>dictionaries[language][key]??en[key as keyof typeof en]??key;}
