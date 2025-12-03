import React, { useEffect, useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ActivityIndicator,
  RefreshControl,
  ScrollView,
} from 'react-native';
import { useNavigation } from '@react-navigation/native';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { ToolList, CategoryFilter } from '../components/ToolList';
import { ToolInfo, ToolCategory } from '../types';
import apiService from '../services/api';

type RootStackParamList = {
  Home: undefined;
  Tool: { tool: ToolInfo };
  Settings: undefined;
};

type NavigationProp = NativeStackNavigationProp<RootStackParamList, 'Home'>;

export const HomeScreen: React.FC = () => {
  const navigation = useNavigation<NavigationProp>();
  const [tools, setTools] = useState<ToolInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedCategory, setSelectedCategory] = useState<ToolCategory | null>(null);

  const loadTools = async () => {
    try {
      setError(null);
      const toolList = await apiService.getTools();
      setTools(toolList);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load tools');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadTools();
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    loadTools();
  };

  const handleSelectTool = (tool: ToolInfo) => {
    navigation.navigate('Tool', { tool });
  };

  if (loading) {
    return (
      <View style={styles.centered}>
        <ActivityIndicator size="large" color="#3B82F6" />
        <Text style={styles.loadingText}>Loading tools...</Text>
      </View>
    );
  }

  if (error) {
    return (
      <ScrollView
        style={styles.container}
        contentContainerStyle={styles.centered}
        refreshControl={
          <RefreshControl refreshing={refreshing} onRefresh={handleRefresh} />
        }
      >
        <Text style={styles.errorIcon}>⚠️</Text>
        <Text style={styles.errorText}>{error}</Text>
        <Text style={styles.errorHint}>Pull to refresh or check your connection</Text>
      </ScrollView>
    );
  }

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.title}>Netshoot</Text>
        <Text style={styles.subtitle}>Network Troubleshooting Tools</Text>
      </View>
      <CategoryFilter
        selectedCategory={selectedCategory}
        onSelectCategory={setSelectedCategory}
      />
      <ToolList
        tools={tools}
        onSelectTool={handleSelectTool}
        selectedCategory={selectedCategory}
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#1a1a2e',
  },
  header: {
    padding: 16,
    paddingTop: 60,
    backgroundColor: '#1a1a2e',
  },
  title: {
    fontSize: 32,
    fontWeight: 'bold',
    color: '#fff',
  },
  subtitle: {
    fontSize: 14,
    color: '#888',
    marginTop: 4,
  },
  centered: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#1a1a2e',
  },
  loadingText: {
    color: '#888',
    marginTop: 16,
  },
  errorIcon: {
    fontSize: 48,
    marginBottom: 16,
  },
  errorText: {
    color: '#EF4444',
    fontSize: 16,
    textAlign: 'center',
    marginBottom: 8,
  },
  errorHint: {
    color: '#888',
    fontSize: 14,
  },
});

export default HomeScreen;
