import React, { useState } from 'react';
import {
  View,
  TextInput,
  TouchableOpacity,
  Text,
  StyleSheet,
  ScrollView,
  ActivityIndicator,
} from 'react-native';
import { ToolResponse } from '../types';

interface ToolFormProps {
  title: string;
  description: string;
  fields: ToolField[];
  onSubmit: (values: Record<string, any>) => Promise<ToolResponse>;
}

interface ToolField {
  name: string;
  label: string;
  placeholder?: string;
  required?: boolean;
  type?: 'text' | 'number' | 'boolean';
  defaultValue?: any;
}

export const ToolForm: React.FC<ToolFormProps> = ({
  title,
  description,
  fields,
  onSubmit,
}) => {
  const [values, setValues] = useState<Record<string, any>>(() => {
    const initial: Record<string, any> = {};
    fields.forEach((field) => {
      initial[field.name] = field.defaultValue ?? '';
    });
    return initial;
  });
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ToolResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async () => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await onSubmit(values);
      setResult(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const handleValueChange = (name: string, value: any, type?: string) => {
    if (type === 'number') {
      setValues({ ...values, [name]: value ? parseInt(value, 10) : undefined });
    } else if (type === 'boolean') {
      setValues({ ...values, [name]: !values[name] });
    } else {
      setValues({ ...values, [name]: value });
    }
  };

  return (
    <ScrollView style={styles.container}>
      <Text style={styles.title}>{title}</Text>
      <Text style={styles.description}>{description}</Text>

      <View style={styles.form}>
        {fields.map((field) => (
          <View key={field.name} style={styles.fieldContainer}>
            <Text style={styles.label}>
              {field.label}
              {field.required && <Text style={styles.required}> *</Text>}
            </Text>
            {field.type === 'boolean' ? (
              <TouchableOpacity
                style={[
                  styles.checkbox,
                  values[field.name] && styles.checkboxChecked,
                ]}
                onPress={() => handleValueChange(field.name, null, 'boolean')}
              >
                <Text style={styles.checkboxText}>
                  {values[field.name] ? '✓' : ''}
                </Text>
              </TouchableOpacity>
            ) : (
              <TextInput
                style={styles.input}
                value={String(values[field.name] ?? '')}
                onChangeText={(text) =>
                  handleValueChange(field.name, text, field.type)
                }
                placeholder={field.placeholder}
                placeholderTextColor="#666"
                keyboardType={field.type === 'number' ? 'numeric' : 'default'}
              />
            )}
          </View>
        ))}

        <TouchableOpacity
          style={[styles.button, loading && styles.buttonDisabled]}
          onPress={handleSubmit}
          disabled={loading}
        >
          {loading ? (
            <ActivityIndicator color="#fff" />
          ) : (
            <Text style={styles.buttonText}>Execute</Text>
          )}
        </TouchableOpacity>
      </View>

      {error && (
        <View style={styles.errorContainer}>
          <Text style={styles.errorText}>{error}</Text>
        </View>
      )}

      {result && (
        <View style={styles.resultContainer}>
          <View style={styles.resultHeader}>
            <Text style={styles.resultTitle}>Result</Text>
            <View
              style={[
                styles.statusBadge,
                result.success ? styles.statusSuccess : styles.statusError,
              ]}
            >
              <Text style={styles.statusText}>
                {result.success ? 'Success' : 'Failed'}
              </Text>
            </View>
          </View>
          <ScrollView style={styles.outputContainer} horizontal>
            <Text style={styles.output} selectable>
              {result.output || result.error || 'No output'}
            </Text>
          </ScrollView>
          {result.exit_code !== 0 && (
            <Text style={styles.exitCode}>Exit Code: {result.exit_code}</Text>
          )}
        </View>
      )}
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#1a1a2e',
    padding: 16,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#fff',
    marginBottom: 8,
  },
  description: {
    fontSize: 14,
    color: '#888',
    marginBottom: 24,
  },
  form: {
    marginBottom: 24,
  },
  fieldContainer: {
    marginBottom: 16,
  },
  label: {
    fontSize: 14,
    color: '#fff',
    marginBottom: 8,
  },
  required: {
    color: '#EF4444',
  },
  input: {
    backgroundColor: '#2d2d44',
    borderRadius: 8,
    padding: 12,
    color: '#fff',
    fontSize: 16,
    borderWidth: 1,
    borderColor: '#3d3d5c',
  },
  checkbox: {
    width: 32,
    height: 32,
    borderRadius: 6,
    backgroundColor: '#2d2d44',
    borderWidth: 1,
    borderColor: '#3d3d5c',
    justifyContent: 'center',
    alignItems: 'center',
  },
  checkboxChecked: {
    backgroundColor: '#3B82F6',
    borderColor: '#3B82F6',
  },
  checkboxText: {
    color: '#fff',
    fontSize: 18,
  },
  button: {
    backgroundColor: '#3B82F6',
    borderRadius: 8,
    padding: 16,
    alignItems: 'center',
    marginTop: 16,
  },
  buttonDisabled: {
    opacity: 0.7,
  },
  buttonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: 'bold',
  },
  errorContainer: {
    backgroundColor: 'rgba(239, 68, 68, 0.2)',
    borderRadius: 8,
    padding: 16,
    marginBottom: 16,
  },
  errorText: {
    color: '#EF4444',
  },
  resultContainer: {
    backgroundColor: '#2d2d44',
    borderRadius: 8,
    padding: 16,
    marginBottom: 32,
  },
  resultHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 16,
  },
  resultTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#fff',
  },
  statusBadge: {
    paddingHorizontal: 12,
    paddingVertical: 4,
    borderRadius: 12,
  },
  statusSuccess: {
    backgroundColor: 'rgba(16, 185, 129, 0.2)',
  },
  statusError: {
    backgroundColor: 'rgba(239, 68, 68, 0.2)',
  },
  statusText: {
    fontSize: 12,
    fontWeight: 'bold',
    color: '#fff',
  },
  outputContainer: {
    backgroundColor: '#1a1a2e',
    borderRadius: 8,
    padding: 12,
    maxHeight: 300,
  },
  output: {
    color: '#10B981',
    fontFamily: 'monospace',
    fontSize: 12,
  },
  exitCode: {
    color: '#888',
    fontSize: 12,
    marginTop: 8,
  },
});

export default ToolForm;
