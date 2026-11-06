import React, { useState, useEffect } from 'react';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import api from '../utils/api';
import { useTheme } from '../context/ThemeContext';

const GENERIC_COLORS = [
  '#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8',
  '#FF6B6B', '#A28FD0', '#82CA9D', '#FF6666', '#66CCFF',
  '#FFB6C1', '#FFD700', '#8DD1E1', '#D0ED57', '#A0522D',
  '#CD5C5C', '#4B0082', '#00CED1', '#9370DB', '#3CB371',
];

const STATUS_CHART_COLORS = {
  'COMPILATION_SUCCESS': '#a6c43aff',
  'COMPILATION_FAILED': '#e97c00ff',
  'VERIFICATION_SUCCESS': '#20a024ff',
  'VERIFICATION_ERROR': '#FF4444',
  'VERIFICATION_TIMEOUT': '#cf910aff',
  'FIXING_SUCCESS': '#8884D8',
  'GENERATION_FAILED': '#FF8A80',
  'GENERATION_SUCCESS': '#3965f6ff',
  'GROUND_TRUTH': '#607D8B',
  'DEFAULT': '#A0AEC0'
};

const LABEL_CHART_COLORS = {
  'SAFE': '#4CAF50',
  'VULNERABLE': '#FF4444',
  'UNKNOWN': '#6f7071'
};

const Stats = () => {
  const [stats, setStats] = useState(null);
  const [extStats, setExtStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const { dark } = useTheme();

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const [data, ext] = await Promise.all([api.getStats(), api.getExtendedStats()]);
        setStats(data);
        setExtStats(ext);
      } catch (err) {
        console.error('Error fetching stats:', err);
        setError('Failed to load statistics');
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
    const interval = setInterval(fetchStats, 30000);
    return () => clearInterval(interval);
  }, []);

  // Chart theme helpers
  const gridColor   = dark ? '#374151' : '#e5e7eb';
  const tickColor   = dark ? '#9CA3AF' : '#6B7280';
  const tooltipStyle = dark
    ? { backgroundColor: '#1f2937', border: '1px solid #374151', color: '#f9fafb' }
    : {};

  if (loading) {
    return (
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
        <div className="animate-pulse">
          <div className="h-6 bg-gray-200 dark:bg-gray-700 rounded w-1/4 mb-4"></div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="h-32 bg-gray-200 dark:bg-gray-700 rounded"></div>
            <div className="h-32 bg-gray-200 dark:bg-gray-700 rounded"></div>
            <div className="h-32 bg-gray-200 dark:bg-gray-700 rounded"></div>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md p-4 text-red-600 dark:text-red-400">
          {error}
        </div>
      </div>
    );
  }

  if (!stats) return null;

  const statusData = (stats.status_counts || []).map(item => ({ name: item.status, value: item.count }));
  const labelData  = Object.entries(stats.label_counts || {}).map(([name, value]) => ({ name, value }));
  const modelData  = Object.entries(stats.model_counts || {}).map(([name, value]) => ({ name, value }));

  return (
    <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
      <h2 className="text-xl font-semibold text-gray-800 dark:text-white mb-4">Dashboard Statistics</h2>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
        <div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg">
          <div className="text-blue-500 dark:text-blue-400 text-sm font-medium uppercase">Total Snippets</div>
          <div className="mt-2 text-3xl font-bold text-gray-900 dark:text-white">{stats.total_snippets}</div>
        </div>

        <div className="bg-green-50 dark:bg-green-900/20 p-4 rounded-lg">
          <div className="text-green-500 dark:text-green-400 text-sm font-medium uppercase">Safe</div>
          <div className="mt-2 text-3xl font-bold text-gray-900 dark:text-white">{stats.safe_count}</div>
        </div>

        <div className="bg-red-50 dark:bg-red-900/20 p-4 rounded-lg">
          <div className="text-red-500 dark:text-red-400 text-sm font-medium uppercase">Vulnerable</div>
          <div className="mt-2 text-3xl font-bold text-gray-900 dark:text-white">{stats.vulnerable_count}</div>
        </div>

        <div className="bg-yellow-50 dark:bg-yellow-900/20 p-4 rounded-lg">
          <div className="text-yellow-600 dark:text-yellow-400 text-sm font-medium uppercase">Vulnerability Rate</div>
          <div className="mt-2 text-3xl font-bold text-gray-900 dark:text-white">
            {stats.safe_count + stats.vulnerable_count > 0
              ? ((stats.vulnerable_count / (stats.safe_count + stats.vulnerable_count)) * 100).toFixed(1) + '%'
              : 'N/A'}
          </div>
        </div>

        <div className="bg-indigo-50 dark:bg-indigo-900/20 p-4 rounded-lg">
          <div className="text-indigo-600 dark:text-indigo-400 text-sm font-medium uppercase">Compilation Rate</div>
          <div className="mt-2 text-3xl font-bold text-gray-900 dark:text-white">
            {extStats?.compilation_rate != null
              ? (extStats.compilation_rate * 100).toFixed(1) + '%'
              : '—'}
          </div>
          {extStats && (
            <div className="mt-1 text-xs text-gray-400 dark:text-gray-500">
              {extStats.compile_success} ok · {extStats.compile_fail} failed
            </div>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
        <div className="bg-gray-50 dark:bg-gray-700 p-4 rounded-lg">
          <h3 className="text-lg font-medium text-gray-800 dark:text-gray-100 mb-4">Status Distribution</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={statusData} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={gridColor} />
                <XAxis dataKey="name" tick={{ fontSize: 12, fill: tickColor }} />
                <YAxis tick={{ fill: tickColor }} />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="value">
                  {statusData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={STATUS_CHART_COLORS[entry.name] || STATUS_CHART_COLORS['DEFAULT']} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-gray-50 dark:bg-gray-700 p-4 rounded-lg">
          <h3 className="text-lg font-medium text-gray-800 dark:text-gray-100 mb-4">Label Distribution</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={labelData}
                  cx="50%"
                  cy="50%"
                  outerRadius={80}
                  dataKey="value"
                  nameKey="name"
                  label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(1)}%`}
                >
                  {labelData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={LABEL_CHART_COLORS[entry.name] || LABEL_CHART_COLORS['UNKNOWN']} />
                  ))}
                </Pie>
                <Tooltip contentStyle={tooltipStyle} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="mt-6">
        <h3 className="text-lg font-medium text-gray-800 dark:text-gray-100 mb-4">Model Distribution</h3>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={modelData} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke={gridColor} />
              <XAxis dataKey="name" tick={{ fontSize: 12, fill: tickColor }} />
              <YAxis tick={{ fill: tickColor }} />
              <Tooltip contentStyle={tooltipStyle} />
              <Bar dataKey="value">
                {modelData.map((_, index) => (
                  <Cell key={`cell-${index}`} fill={GENERIC_COLORS[index % GENERIC_COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {extStats && (
        <>
          <div className="mt-8 border-t border-gray-200 dark:border-gray-600 pt-6">
            <h3 className="text-lg font-medium text-gray-800 dark:text-gray-100 mb-4">Code Metrics — Safe &amp; Vulnerable</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {[
                { label: 'Lines of Code (LOC)', data: extStats.loc },
                { label: 'Cyclomatic Complexity', data: extStats.cc },
                { label: 'Nesting Depth', data: extStats.nd },
              ].map(({ label, data }) => (
                <div key={label} className="bg-gray-50 dark:bg-gray-700 p-4 rounded-lg">
                  <h4 className="text-sm font-medium text-gray-600 dark:text-gray-300 mb-3">{label}</h4>
                  <div className="grid grid-cols-3 gap-2 text-center">
                    <div>
                      <div className="text-xs text-gray-400 dark:text-gray-500 uppercase tracking-wide">Min</div>
                      <div className="text-xl font-bold text-gray-700 dark:text-gray-200 mt-1">{data?.min ?? '—'}</div>
                    </div>
                    <div className="border-x border-gray-200 dark:border-gray-600">
                      <div className="text-xs text-indigo-400 uppercase tracking-wide">Mean</div>
                      <div className="text-xl font-bold text-indigo-600 dark:text-indigo-400 mt-1">{data?.mean ?? '—'}</div>
                    </div>
                    <div>
                      <div className="text-xs text-gray-400 dark:text-gray-500 uppercase tracking-wide">Max</div>
                      <div className="text-xl font-bold text-gray-700 dark:text-gray-200 mt-1">{data?.max ?? '—'}</div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
            {Object.keys(extStats.cwe_distribution_vulnerable || {}).length > 0 && (
              <div className="bg-gray-50 dark:bg-gray-700 p-4 rounded-lg">
                <h3 className="text-lg font-medium text-gray-800 dark:text-gray-100 mb-4">CWE Distribution — Verified Vulnerable</h3>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      data={Object.entries(extStats.cwe_distribution_vulnerable).map(([name, value]) => ({ name, value }))}
                      layout="vertical"
                      margin={{ top: 5, right: 30, left: 80, bottom: 5 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke={gridColor} />
                      <XAxis type="number" allowDecimals={false} tick={{ fill: tickColor }} />
                      <YAxis dataKey="name" type="category" tick={{ fontSize: 11, fill: tickColor }} width={75} />
                      <Tooltip contentStyle={tooltipStyle} />
                      <Bar dataKey="value" fill="#FF4444" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}

            {Object.keys(extStats.language_distribution || {}).length > 0 && (
              <div className="bg-gray-50 dark:bg-gray-700 p-4 rounded-lg">
                <h3 className="text-lg font-medium text-gray-800 dark:text-gray-100 mb-4">Language Distribution</h3>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={Object.entries(extStats.language_distribution).map(([name, value]) => ({ name, value }))}
                        cx="50%"
                        cy="50%"
                        outerRadius={80}
                        dataKey="value"
                        nameKey="name"
                        label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(1)}%`}
                      >
                        {Object.keys(extStats.language_distribution).map((_, index) => (
                          <Cell key={`lang-${index}`} fill={GENERIC_COLORS[index % GENERIC_COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={tooltipStyle} />
                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
};

export default Stats;
