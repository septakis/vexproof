import React from 'react';
import { createRoot } from 'react-dom/client';
import { LineChart, Line, XAxis, YAxis, Tooltip, Treemap } from 'recharts';

const visits = [{ day: 'Mon', visits: 120 }, { day: 'Tue', visits: 180 }, { day: 'Wed', visits: 150 }];
const storage = [{ name: 'Images', size: 420 }, { name: 'Video', size: 910 }, { name: 'Docs', size: 130 }];

function App() {
  return (
    <>
      <LineChart width={480} height={240} data={visits}>
        <XAxis dataKey="day" /><YAxis /><Tooltip />
        <Line type="monotone" dataKey="visits" />
      </LineChart>
      <Treemap width={480} height={240} data={storage} dataKey="size" />
    </>
  );
}
createRoot(document.getElementById('root')).render(<App />);
