export const dynamic = "force-dynamic";
import { marked } from 'marked';
import yaml from 'js-yaml';
import Search from './components/Search';

const config = yaml.load('title: Invoices\nnotice: "**Due** on the 1st"') as { title: string; notice: string };

export default function Page() {
  return (
    <main>
      <h1>{config.title}</h1>
      <div dangerouslySetInnerHTML={{ __html: marked.parse(config.notice) }} />
      <Search />
    </main>
  );
}
