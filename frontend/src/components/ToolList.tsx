import React from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  FlatList,
} from 'react-native';
import { ToolInfo, TOOL_CATEGORIES, ToolCategory } from '../types';

interface ToolListProps {
  tools: ToolInfo[];
  onSelectTool: (tool: ToolInfo) => void;
  selectedCategory?: ToolCategory | null;
}

export const ToolList: React.FC<ToolListProps> = ({
  tools,
  onSelectTool,
  selectedCategory,
}) => {
  const filteredTools = selectedCategory
    ? tools.filter((tool) => tool.category === selectedCategory)
    : tools;

  const renderItem = ({ item }: { item: ToolInfo }) => {
    const category = TOOL_CATEGORIES[item.category as ToolCategory] || {
      icon: '🔧',
      color: '#64748B',
    };

    return (
      <TouchableOpacity
        style={styles.toolItem}
        onPress={() => onSelectTool(item)}
      >
        <View style={[styles.iconContainer, { backgroundColor: category.color + '20' }]}>
          <Text style={styles.icon}>{category.icon}</Text>
        </View>
        <View style={styles.toolInfo}>
          <Text style={styles.toolName}>{item.name}</Text>
          <Text style={styles.toolDescription} numberOfLines={2}>
            {item.description}
          </Text>
        </View>
        <Text style={styles.arrow}>›</Text>
      </TouchableOpacity>
    );
  };

  return (
    <FlatList
      data={filteredTools}
      renderItem={renderItem}
      keyExtractor={(item) => item.name}
      contentContainerStyle={styles.container}
      ItemSeparatorComponent={() => <View style={styles.separator} />}
    />
  );
};

interface CategoryFilterProps {
  selectedCategory: ToolCategory | null;
  onSelectCategory: (category: ToolCategory | null) => void;
}

export const CategoryFilter: React.FC<CategoryFilterProps> = ({
  selectedCategory,
  onSelectCategory,
}) => {
  const categories = Object.entries(TOOL_CATEGORIES) as [ToolCategory, typeof TOOL_CATEGORIES[ToolCategory]][];

  return (
    <FlatList
      horizontal
      showsHorizontalScrollIndicator={false}
      data={[{ key: 'all', label: 'All', icon: '🔍', color: '#6366F1' }, ...categories.map(([key, value]) => ({ key, ...value }))]}
      renderItem={({ item }) => (
        <TouchableOpacity
          style={[
            styles.categoryChip,
            { backgroundColor: item.color + '20' },
            (item.key === 'all' ? selectedCategory === null : selectedCategory === item.key) && {
              backgroundColor: item.color,
            },
          ]}
          onPress={() => onSelectCategory(item.key === 'all' ? null : (item.key as ToolCategory))}
        >
          <Text style={styles.categoryIcon}>{item.icon}</Text>
          <Text style={[
            styles.categoryLabel,
            (item.key === 'all' ? selectedCategory === null : selectedCategory === item.key) && styles.categoryLabelActive,
          ]}>
            {item.label}
          </Text>
        </TouchableOpacity>
      )}
      keyExtractor={(item) => item.key}
      contentContainerStyle={styles.categoryContainer}
    />
  );
};

const styles = StyleSheet.create({
  container: {
    padding: 16,
  },
  toolItem: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#2d2d44',
    borderRadius: 12,
    padding: 16,
  },
  iconContainer: {
    width: 48,
    height: 48,
    borderRadius: 12,
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 12,
  },
  icon: {
    fontSize: 24,
  },
  toolInfo: {
    flex: 1,
  },
  toolName: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#fff',
    marginBottom: 4,
  },
  toolDescription: {
    fontSize: 12,
    color: '#888',
  },
  arrow: {
    fontSize: 24,
    color: '#888',
    marginLeft: 8,
  },
  separator: {
    height: 12,
  },
  categoryContainer: {
    paddingHorizontal: 16,
    paddingVertical: 12,
  },
  categoryChip: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 12,
    paddingVertical: 8,
    borderRadius: 20,
    marginRight: 8,
  },
  categoryIcon: {
    fontSize: 16,
    marginRight: 6,
  },
  categoryLabel: {
    fontSize: 13,
    color: '#fff',
    fontWeight: '500',
  },
  categoryLabelActive: {
    fontWeight: 'bold',
  },
});

export default ToolList;
