import React, { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { format } from 'date-fns';
import api from '../utils/api';

const LABEL_COLORS = {
  SAFE:       'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
  VULNERABLE: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
  UNKNOWN:    'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-400',
};

const PAGE_SIZE = 50;

const Seeds = () => {
  const [seeds, setSeeds]             = useState([]);
  const [languages, setLanguages]     = useState([]);
  const [loading, setLoading]         = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [hasMore, setHasMore]         = useState(true);
  const [error, setError]             = useState(null);
  const [skip, setSkip]               = useState(0);
  const [lastRefresh, setLastRefresh] = useState(new Date());

  const [filters, setFilters] = useState({
    language: '', dataset: '', cve: '', project: '', label: '',
  });

  const buildParams = useCallback((extraSkip = 0) => {
    const p = { skip: extraSkip, limit: PAGE_SIZE, type: 'SEED', sort_by: 'updated_at', sort_desc: true };
    if (filters.language) p.language = filters.language;
    if (filters.dataset)  p.dataset  = filters.dataset;
    if (filters.cve)      p.cve      = filters.cve;
    if (filters.label)    p.label    = filters.label;
    return p;
  }, [filters]);

  const fetchSeeds = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [data, langsData] = await Promise.all([api.getSnippets(buildParams(0)), api.getLanguages()]);
      const list = Array.isArray(data) ? data : [];
      setSeeds(list);
      setSkip(PAGE_SIZE);
      setHasMore(list.length === PAGE_SIZE);
      setLanguages(Array.isArray(langsData?.languages) ? langsData.languages : []);
      setLastRefresh(new Date());
    } catch (err) {
      console.error(err);
      setError('Failed to load seeds.');
    } finally {
      setLoading(false);
    }
  }, [buildParams]);

  const loadMore = useCallback(async () => {
    if (!hasMore || loadingMore) return;
    setLoadingMore(true);
    try {
      const more = await api.getSnippets(buildParams(skip));
      const list = Array.isArray(more) ? more : [];
      if (list.length < PAGE_SIZE) setHasMore(false);
      setSeeds(prev => [...prev, ...list]);
      setSkip(prev => prev + PAGE_SIZE);
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingMore(false);
    }
  }, [skip, hasMore, loadingMore, buildParams]);

  useEffect(() => { fetchSeeds(); }, [fetchSeeds]);

  const handleFilter = (e) => setFilters(prev => ({ ...prev, [e.target.name]: e.target.value }));

  const inputCls = 'w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-200 px-3 py-2 text-sm';

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h2 className="text-xl font-semibold text-gray-800 dark:text-white">Ground Truth Seeds</h2>
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
              {seeds.length} seeds loaded · Last updated: {format(lastRefresh, 'HH:mm:ss')}
            </p>
          </div>
          <button onClick={fetchSeeds}
            className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md text-sm text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600">
            Refresh
          </button>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-5">
          <div>
            <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Language</label>
            <select name="language" value={filters.language} onChange={handleFilter} className={inputCls}>
              <option value="">All</option>
              {languages.map(l => <option key={l} value={l}>{l}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Dataset</label>
            <input name="dataset" value={filters.dataset} onChange={handleFilter}
              placeholder="e.g. ICVul" className={inputCls} />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">CVE</label>
            <input name="cve" value={filters.cve} onChange={handleFilter}
              placeholder="e.g. CVE-2021" className={inputCls} />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Label</label>
            <select name="label" value={filters.label} onChange={handleFilter} className={inputCls}>
              <option value="">All</option>
              <option value="SAFE">Safe</option>
              <option value="VULNERABLE">Vulnerable</option>
              <option value="UNKNOWN">Unknown</option>
            </select>
          </div>
          <div className="flex items-end">
            <button
              onClick={() => setFilters({ language: '', dataset: '', cve: '', project: '', label: '' })}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md text-sm text-gray-500 dark:text-gray-400 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600">
              Clear
            </button>
          </div>
        </div>

        {loading ? (
          <div className="flex justify-center items-center py-12">
            <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-indigo-500" />
          </div>
        ) : error ? (
          <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md p-4 text-red-600 dark:text-red-400">{error}</div>
        ) : seeds.length === 0 ? (
          <div className="text-center py-12 text-gray-500 dark:text-gray-400">No seeds found with the selected filters.</div>
        ) : (
          <>
            <div className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
              <div className="overflow-x-auto overflow-y-auto max-h-[65vh]">
                <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700 text-sm">
                  <thead className="bg-gray-50 dark:bg-gray-700 sticky top-0 z-10">
                    <tr>
                      {['UUID','Dataset','CVE','Project','Language','CWEs','Label','Commit','Repo','Updated'].map(h => (
                        <th key={h} className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wide whitespace-nowrap">
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-100 dark:divide-gray-700">
                    {seeds.map(s => (
                      <tr key={s.uuid} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                        <td className="px-4 py-3 whitespace-nowrap">
                          <Link to={`/snippets/${s.uuid}`} className="font-mono text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 text-xs font-medium">
                            {s.uuid.substring(0, 8)}…
                          </Link>
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          {s.dataset
                            ? <span className="px-2 py-0.5 rounded-full text-xs bg-indigo-100 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-400">{s.dataset}</span>
                            : <span className="text-gray-300 dark:text-gray-600">—</span>}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          {s.cve
                            ? <span className="font-mono text-xs text-orange-700 dark:text-orange-400">{s.cve}</span>
                            : <span className="text-gray-300 dark:text-gray-600">—</span>}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap text-xs text-gray-600 dark:text-gray-300 max-w-[140px] truncate" title={s.project}>
                          {s.project || <span className="text-gray-300 dark:text-gray-600">—</span>}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          {s.language
                            ? <span className="px-2 py-0.5 rounded text-xs bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300">{s.language}</span>
                            : <span className="text-gray-300 dark:text-gray-600">—</span>}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex flex-wrap gap-1">
                            {s.cwes && s.cwes.length > 0
                              ? s.cwes.map(cwe => (
                                  <span key={cwe} className="px-1.5 py-0.5 rounded text-xs bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400">{cwe}</span>
                                ))
                              : <span className="text-gray-300 dark:text-gray-600">—</span>}
                          </div>
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          {s.label
                            ? <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${LABEL_COLORS[s.label] || 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-400'}`}>{s.label}</span>
                            : <span className="text-gray-300 dark:text-gray-600">—</span>}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          {s.commit_hash
                            ? <span className="font-mono text-xs text-gray-500 dark:text-gray-400">{s.commit_hash.substring(0, 7)}</span>
                            : <span className="text-gray-300 dark:text-gray-600">—</span>}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          {s.repo_url
                            ? <a href={s.repo_url} target="_blank" rel="noreferrer"
                                className="text-xs text-blue-500 dark:text-blue-400 hover:underline truncate max-w-[120px] block">
                                {s.repo_url.replace('https://github.com/', '')}
                              </a>
                            : <span className="text-gray-300 dark:text-gray-600">—</span>}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap text-xs text-gray-500 dark:text-gray-400">
                          {format(new Date(s.updated_at), 'MMM d HH:mm')}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
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
                  ) : `Load more (showing ${seeds.length})`}
                </button>
              </div>
            )}
            {!hasMore && seeds.length > 0 && (
              <p className="text-center text-xs text-gray-400 dark:text-gray-500 py-3">All {seeds.length} seeds loaded.</p>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default Seeds;
