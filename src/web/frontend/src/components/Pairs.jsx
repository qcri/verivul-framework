import React, { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { format } from 'date-fns';
import api from '../utils/api';

const LABEL_COLORS = {
  SAFE:       'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
  VULNERABLE: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
  UNKNOWN:    'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-400',
};

const STATUS_COLORS = {
  VERIFICATION_SUCCESS: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
  COMPILATION_SUCCESS:  'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
  GENERATION_SUCCESS:   'bg-indigo-100 text-indigo-800 dark:bg-indigo-900/30 dark:text-indigo-400',
  COMPILATION_FAILED:   'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400',
  VERIFICATION_ERROR:   'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
};

const badge = (text, colorMap) => {
  const cls = colorMap[text] || 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-400';
  return <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${cls}`}>{text}</span>;
};

const PAIR_TYPE_CONFIG = {
  fix:       { label: 'Fix',       bg: 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-900/30 dark:text-emerald-400 dark:border-emerald-700' },
  injection: { label: 'Injection', bg: 'bg-rose-50 text-rose-700 border-rose-200 dark:bg-rose-900/30 dark:text-rose-400 dark:border-rose-700' },
  unknown:   { label: 'Unknown',   bg: 'bg-gray-50 text-gray-600 border-gray-200 dark:bg-gray-700 dark:text-gray-400 dark:border-gray-600' },
};

const SnippetCell = ({ snippet }) => (
  <div className="space-y-1">
    <Link to={`/snippets/${snippet.uuid}`}
      className="font-mono text-sm text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 font-medium">
      {snippet.uuid.substring(0, 8)}…
    </Link>
    <div className="flex flex-wrap gap-1 mt-1">
      {badge(snippet.label || 'UNKNOWN', LABEL_COLORS)}
      {badge(snippet.status, STATUS_COLORS)}
    </div>
    {snippet.cwes && snippet.cwes.length > 0 && (
      <div className="flex flex-wrap gap-1 mt-1">
        {snippet.cwes.map(cwe => (
          <span key={cwe} className="px-1.5 py-0.5 rounded text-xs bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400">{cwe}</span>
        ))}
      </div>
    )}
  </div>
);

const PAGE_SIZE = 50;

const Pairs = () => {
  const [pairs, setPairs]             = useState([]);
  const [languages, setLanguages]     = useState([]);
  const [totalCount, setTotalCount]   = useState(null);
  const [fixCount, setFixCount]       = useState(null);
  const [injCount, setInjCount]       = useState(null);
  const [loading, setLoading]         = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [hasMore, setHasMore]         = useState(true);
  const [error, setError]             = useState(null);
  const [skip, setSkip]               = useState(0);
  const [filterType, setFilterType]   = useState('');
  const [filterLang, setFilterLang]   = useState('');

  const fetchPairs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = { skip: 0, limit: PAGE_SIZE };
      if (filterType) params.pair_type = filterType;
      if (filterLang) params.language  = filterLang;
      const langParam = filterLang || undefined;
      const [data, langsData, countData, fixData, injData] = await Promise.all([
        api.getPairs(params),
        api.getLanguages(),
        api.getPairsCount({ pair_type: filterType || undefined, language: langParam }),
        api.getPairsCount({ pair_type: 'fix',       language: langParam }),
        api.getPairsCount({ pair_type: 'injection', language: langParam }),
      ]);
      const list = Array.isArray(data) ? data : [];
      setPairs(list);
      setSkip(PAGE_SIZE);
      setHasMore(list.length === PAGE_SIZE);
      setLanguages(Array.isArray(langsData?.languages) ? langsData.languages : []);
      setTotalCount(countData?.total ?? null);
      setFixCount(fixData?.total ?? null);
      setInjCount(injData?.total ?? null);
    } catch (err) {
      console.error(err);
      setError('Failed to load pairs.');
    } finally {
      setLoading(false);
    }
  }, [filterType, filterLang]);

  const loadMore = useCallback(async () => {
    if (!hasMore || loadingMore) return;
    setLoadingMore(true);
    try {
      const params = { skip, limit: PAGE_SIZE };
      if (filterType) params.pair_type = filterType;
      if (filterLang) params.language  = filterLang;
      const more = await api.getPairs(params);
      const list = Array.isArray(more) ? more : [];
      if (list.length < PAGE_SIZE) setHasMore(false);
      setPairs(prev => [...prev, ...list]);
      setSkip(prev => prev + PAGE_SIZE);
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingMore(false);
    }
  }, [skip, hasMore, loadingMore, filterType, filterLang]);

  useEffect(() => { fetchPairs(); }, [fetchPairs]);

  const selectCls = 'rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-200 px-3 py-2 text-sm';

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h2 className="text-xl font-semibold text-gray-800 dark:text-white">Pairs</h2>
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
              Fix pairs (VULNERABLE → SAFE) and Injection pairs (SAFE → VULNERABLE)
            </p>
          </div>
          <div className="flex items-center gap-3">
            <select value={filterType} onChange={e => setFilterType(e.target.value)} className={selectCls}>
              <option value="">All Types</option>
              <option value="fix">Fix</option>
              <option value="injection">Injection</option>
            </select>
            <select value={filterLang} onChange={e => setFilterLang(e.target.value)} className={selectCls}>
              <option value="">All Languages</option>
              {languages.map(l => <option key={l} value={l}>{l}</option>)}
            </select>
            <button onClick={fetchPairs}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md text-sm text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600">
              Refresh
            </button>
          </div>
        </div>

        {!loading && (
          <div className="grid grid-cols-3 gap-4 mb-6">
            <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4 text-center">
              <div className="text-2xl font-bold text-gray-800 dark:text-white">
                {totalCount !== null ? (
                  <>{pairs.length}<span className="text-base font-normal text-gray-400 dark:text-gray-500"> / {totalCount}</span></>
                ) : pairs.length}
              </div>
              <div className="text-xs text-gray-500 dark:text-gray-400 uppercase mt-1">Loaded / Total</div>
            </div>
            <div className="bg-emerald-50 dark:bg-emerald-900/20 rounded-lg p-4 text-center">
              <div className="text-2xl font-bold text-emerald-700 dark:text-emerald-400">{fixCount ?? '—'}</div>
              <div className="text-xs text-emerald-600 dark:text-emerald-500 uppercase mt-1">Fix Pairs</div>
            </div>
            <div className="bg-rose-50 dark:bg-rose-900/20 rounded-lg p-4 text-center">
              <div className="text-2xl font-bold text-rose-700 dark:text-rose-400">{injCount ?? '—'}</div>
              <div className="text-xs text-rose-600 dark:text-rose-500 uppercase mt-1">Injection Pairs</div>
            </div>
          </div>
        )}

        {loading ? (
          <div className="flex justify-center items-center py-12">
            <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-indigo-500" />
          </div>
        ) : error ? (
          <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md p-4 text-red-600 dark:text-red-400">{error}</div>
        ) : pairs.length === 0 ? (
          <div className="text-center py-12 text-gray-500 dark:text-gray-400">
            No pairs yet. Pairs are created after verification completes.
          </div>
        ) : (
          <>
            <div className="overflow-x-auto overflow-y-auto max-h-[65vh] border border-gray-200 dark:border-gray-700 rounded-lg">
              <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                <thead className="bg-gray-50 dark:bg-gray-700 sticky top-0 z-10">
                  <tr>
                    {['Type', 'Original', '', 'Derived', 'Model', 'Seed', 'Updated'].map((h, i) => (
                      <th key={i} className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-100 dark:divide-gray-700">
                  {pairs.map(pair => {
                    const cfg = PAIR_TYPE_CONFIG[pair.pair_type] || PAIR_TYPE_CONFIG.unknown;
                    return (
                      <tr key={`${pair.original.uuid}-${pair.derived.uuid}`} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                        <td className="px-4 py-4 whitespace-nowrap">
                          <span className={`px-2 py-1 rounded-full text-xs font-medium border ${cfg.bg}`}>{cfg.label}</span>
                        </td>
                        <td className="px-4 py-4"><SnippetCell snippet={pair.original} /></td>
                        <td className="px-2 py-4 text-center text-gray-400 dark:text-gray-500 text-lg">→</td>
                        <td className="px-4 py-4"><SnippetCell snippet={pair.derived} /></td>
                        <td className="px-4 py-4 whitespace-nowrap text-sm text-gray-600 dark:text-gray-300">{pair.original.generation_model}</td>
                        <td className="px-4 py-4 whitespace-nowrap">
                          <Link to={`/snippets/${pair.seed_uuid}`}
                            className="font-mono text-xs text-blue-500 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300">
                            {pair.seed_uuid.substring(0, 8)}…
                          </Link>
                        </td>
                        <td className="px-4 py-4 whitespace-nowrap text-xs text-gray-500 dark:text-gray-400">
                          {format(new Date(pair.derived.updated_at), 'MMM d HH:mm')}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {hasMore && (
              <div className="mt-4 flex justify-center">
                <button
                  onClick={loadMore}
                  disabled={loadingMore}
                  className="px-5 py-2 border border-gray-300 dark:border-gray-600 rounded-md text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {loadingMore ? (
                    <span className="flex items-center gap-2">
                      <span className="inline-block w-4 h-4 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
                      Loading…
                    </span>
                  ) : `Load more (showing ${pairs.length})`}
                </button>
              </div>
            )}
            {!hasMore && pairs.length > 0 && (
              <p className="text-center text-xs text-gray-400 dark:text-gray-500 py-3">
                All {totalCount ?? pairs.length} pairs loaded.
              </p>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default Pairs;
