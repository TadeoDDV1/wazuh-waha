import React from 'react';
import Layout from './components/Layout';

const App: React.FC = () => {
  return (
    <Layout>
      {/* The Dashboard component is already included in Layout via DashboardProvider */}
    </Layout>
  );
};

export default App;
