import {describe,it,expect} from 'vitest';
import en from '../src/locales/en.json';
import hy from '../src/locales/hy.json';
import ru from '../src/locales/ru.json';
describe('complete locale catalogs',()=>{
 it('has identical keys for English, Armenian, and Russian',()=>{expect(Object.keys(hy).sort()).toEqual(Object.keys(en).sort());expect(Object.keys(ru).sort()).toEqual(Object.keys(en).sort());});
 it('contains nonempty translations and native Unicode',()=>{for(const catalog of [en,hy,ru])for(const value of Object.values(catalog))expect(value.trim().length).toBeGreaterThan(0);expect(hy.overview).toMatch(/[\u0530-\u058f]/);expect(ru.overview).toMatch(/[\u0400-\u04ff]/);});
});
