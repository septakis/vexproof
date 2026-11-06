'use client';
import { useState } from 'react';
import debounce from 'lodash/debounce';

export default function Search() {
  const [q, setQ] = useState('');
  const update = debounce((v: string) => setQ(v), 200);
  return <><input onChange={(e) => update(e.target.value)} placeholder="Search invoices" /><p>{q}</p></>;
}
