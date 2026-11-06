import React, { useState, useEffect } from 'react';
import api from '../utils/api';

const SlotBar = ({ label, active, total, colorClass }) => {
  const pct = total > 0 ? Math.min(100, (active / total) * 100) : 0;
  const free = Math.max(0, total - active);

  return (
    <div>
      <div className="flex justify-between items-baseline mb-1">
        <span className="text-xs font-medium text-gray-600 dark:text-gray-400">{label}</span>
        <span className="text-xs text-gray-500 dark:text-gray-400">
          <span className={`font-semibold ${colorClass}`}>{active}</span>
          <span className="text-gray-400 dark:text-gray-500"> / {total}</span>
          <span className="ml-1 text-gray-400 dark:text-gray-500">({free} free)</span>
        </span>
      </div>
      <div className="w-full bg-gray-200 dark:bg-gray-600 rounded-full h-2">
        <div
          className={`h-2 rounded-full transition-all duration-500 ${colorClass.replace('text-', 'bg-')}`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
};

const POLL_INTERVAL = 5000;

const ResourcePanel = () => {
  const [data, setData] = useState(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    let mounted = true;
    const fetch = async () => {
      try {
        const res = await api.getResources();
        if (mounted) { setData(res); setError(false); }
      } catch {
        if (mounted) setError(true);
      }
    };
    fetch();
    const id = setInterval(fetch, POLL_INTERVAL);
    return () => { mounted = false; clearInterval(id); };
  }, []);

  if (error || !data) {
    return (
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-4">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">Resource Utilisation</h3>
          <span className="text-xs text-gray-400 dark:text-gray-500">● 5 s refresh</span>
        </div>
        <p className="text-xs text-gray-400 dark:text-gray-500">
          {error ? 'Docker unavailable or API unreachable' : 'Loading…'}
        </p>
      </div>
    );
  }

  const { compilation, verification } = data;
  const compPct  = compilation.total  > 0 ? (compilation.active  / compilation.total)  * 100 : 0;
  const verifPct = verification.total > 0 ? (verification.active / verification.total) * 100 : 0;

  const compColor  = compPct  > 80 ? 'text-red-500'    : compPct  > 50 ? 'text-orange-500' : 'text-blue-500';
  const verifColor = verifPct > 80 ? 'text-red-500'    : verifPct > 50 ? 'text-orange-500' : 'text-green-500';

  return (
    <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">Resource Utilisation</h3>
        <span className="text-xs text-gray-400 dark:text-gray-500">
          {data.docker_available
            ? <span className="text-green-500">● Docker</span>
            : <span className="text-red-400">● Docker unavailable</span>}
          <span className="ml-2">5 s refresh</span>
        </span>
      </div>

      <div className="space-y-3">
        <SlotBar
          label="Compilation slots"
          active={compilation.active}
          total={compilation.total}
          colorClass={compColor}
        />
        <SlotBar
          label="Verification slots"
          active={verification.active}
          total={verification.total}
          colorClass={verifColor}
        />
      </div>

      {/* Active containers detail — collapsed unless busy */}
      {(compilation.active > 0 || verification.active > 0) && (
        <div className="mt-3 pt-3 border-t border-gray-100 dark:border-gray-700 grid grid-cols-2 gap-2">
          {compilation.active > 0 && (
            <div>
              <p className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">Compiler containers</p>
              {compilation.containers.slice(0, 4).map(c => (
                <p key={c.name} className="text-xs font-mono text-gray-400 dark:text-gray-500 truncate">{c.name.replace('verivul-compiler-', '')}</p>
              ))}
              {compilation.containers.length > 4 && (
                <p className="text-xs text-gray-400">+{compilation.containers.length - 4} more</p>
              )}
            </div>
          )}
          {verification.active > 0 && (
            <div>
              <p className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">ESBMC containers</p>
              {verification.containers.slice(0, 4).map(c => (
                <p key={c.name} className="text-xs font-mono text-gray-400 dark:text-gray-500 truncate">{c.name.replace('verivul-esbmc-', '')}</p>
              ))}
              {verification.containers.length > 4 && (
                <p className="text-xs text-gray-400">+{verification.containers.length - 4} more</p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default ResourcePanel;
