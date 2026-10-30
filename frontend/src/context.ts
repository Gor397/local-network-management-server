import { createContext, type ReactNode } from "react";
import type { Identity } from "./types";
export type Field = {
  name: string;
  label: string;
  type?: string;
  value?: any;
  options?: { value: string; label: string }[];
  required?: boolean;
};
export type ModalSpec = {
  title: string;
  fields?: Field[];
  info?: ReactNode;
  submit?: (values: any) => Promise<any>;
  content?: ReactNode;
};
export const WorkContext = createContext<{
  revision: number;
  refresh: () => void;
  modal: (m: ModalSpec | null) => void;
  run: (fn: () => Promise<any>) => Promise<any>;
  identity: Identity;
}>({
  revision: 0,
  refresh: () => {},
  modal: () => {},
  run: async () => {},
  identity: { username: "", role: "viewer", csrf: "", mfa: false },
});
