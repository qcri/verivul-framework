import React from 'react';
import { Link } from 'react-router-dom';
import { SunIcon, MoonIcon } from '@heroicons/react/24/outline';
import { useTheme } from '../context/ThemeContext';

const Navbar = () => {
  const { dark, toggle } = useTheme();

  return (
    <nav className="bg-white dark:bg-gray-900 shadow-sm border-b border-gray-200 dark:border-gray-700">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-16">
          <div className="flex">
            <div className="flex-shrink-0 flex items-center">
              <Link to="/" className="text-xl font-bold text-primary-600">
                VeriVul Dashboard
              </Link>
            </div>
            <div className="hidden sm:ml-6 sm:flex sm:space-x-8">
              <Link
                to="/"
                className="border-primary-500 text-gray-900 dark:text-white inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium"
              >
                Dashboard
              </Link>
              <Link
                to="/seeds"
                className="border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 hover:border-gray-300 dark:hover:border-gray-600 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium"
              >
                Seeds
              </Link>
              <Link
                to="/pairs"
                className="border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 hover:border-gray-300 dark:hover:border-gray-600 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium"
              >
                Pairs
              </Link>
            </div>
          </div>
          <div className="hidden sm:ml-6 sm:flex sm:items-center gap-3">
            <button
              onClick={toggle}
              className="p-2 rounded-md text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
              aria-label="Toggle dark mode"
            >
              {dark
                ? <SunIcon className="h-5 w-5" />
                : <MoonIcon className="h-5 w-5" />}
            </button>
            <span className="px-3 py-1 rounded-full text-sm font-medium bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-400">
              System Active
            </span>
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
