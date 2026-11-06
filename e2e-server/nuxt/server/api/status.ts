import { marked } from 'marked';
import yaml from 'js-yaml';
export default defineEventHandler(() => {
  const cfg = yaml.load('title: Status\nbody: "All **green**"') as { body: string };
  return { html: marked.parse(cfg.body) };
});
