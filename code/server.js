const express = require('express');
const { express: voyagerMiddleware } = require('graphql-voyager/middleware');
const fs = require('fs');
const path = require('path');
const cors = require('cors');

const app = express();
app.use(cors());

// Load your FULL introspection result
const schemaPath = path.join(__dirname, 'full_introspection.json');
let introspectionResult;

try {
  introspectionResult = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
  console.log('Full introspection loaded from full_introspection.json');
} catch (err) {
  console.error('Failed to load JSON:', err.message);
  process.exit(1);
}

// Mock GraphQL endpoint
app.use('/graphql', express.json(), (req, res) => {
  if (req.method === 'POST' && req.body.query?.includes('IntrospectionQuery')) {
    return res.json(introspectionResult); // Already has { data: ... }
  }
  res.status(400).json({ error: 'Only introspection queries allowed' });
});

// Serve Voyager
app.use('/voyager', voyagerMiddleware({
  endpointUrl: '/graphql',
  displayOptions: {
    skipRelay: true,
    skipDeprecated: false,
    showLeafFields: true,
    sortByAlphabet: false,
    hideRoot: false,
  },
}));

const PORT = 3001;
app.listen(PORT, () => {
  console.log(`Voyager: http://localhost:${PORT}/voyager`);
  console.log(`GraphQL Mock: http://localhost:${PORT}/graphql`);
});
