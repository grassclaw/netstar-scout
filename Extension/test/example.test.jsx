import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import React from 'react';

// A simple component to test
function HelloWorld({ name }) {
    return <div>Hello, {name}!</div>;
}

describe('Example Test', () => {
    it('should pass a simple math test', () => {
        expect(1 + 1).toBe(2);
    });

    it('should render the HelloWorld component', () => {
        render(<HelloWorld name="World" />);
        expect(screen.getByText('Hello, World!')).toBeInTheDocument();
    });
});
