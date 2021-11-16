import isPrintableKeyEvent from "is-printable-key-event";
import * as React from "react";
import styled from "styled-components";

type Props = {
  disabled?: boolean;
  readOnly?: boolean;
  onChange?: (text: string) => void;
  onBlur?: React.FocusEventHandler<HTMLSpanElement> | undefined;
  onInput?: React.FormEventHandler<HTMLSpanElement> | undefined;
  onKeyDown?: React.KeyboardEventHandler<HTMLSpanElement> | undefined;
  placeholder?: string;
  maxLength?: number;
  autoFocus?: boolean;
  className?: string;
  children?: React.ReactNode;
  value: string;
};

/**
 * Defines a content editable component with the same interface as a native
 * HTMLInputElement (or, as close as we can get).
 */
function ContentEditable({
  disabled,
  onChange,
  onInput,
  onBlur,
  onKeyDown,
  value,
  children,
  className,
  maxLength,
  autoFocus,
  placeholder,
  readOnly,
  ...rest
}: Props) {
  const ref = React.useRef<HTMLSpanElement>(null);
  const [innerHTML, setInnerHTML] = React.useState<string>(value);
  const lastValue = React.useRef("");

  const wrappedEvent = (
    callback:
      | React.FocusEventHandler<HTMLSpanElement>
      | React.FormEventHandler<HTMLSpanElement>
      | React.KeyboardEventHandler<HTMLSpanElement>
      | undefined
  ) => (event: any) => {
    const text = ref.current?.innerText || "";

    if (maxLength && isPrintableKeyEvent(event) && text.length >= maxLength) {
      event?.preventDefault();
      return;
    }

    if (text !== lastValue.current) {
      lastValue.current = text;
      onChange && onChange(text);
    }

    callback?.(event);
  };

  React.useLayoutEffect(() => {
    if (autoFocus) {
      ref.current?.focus();
    }
  });

  React.useEffect(() => {
    if (value !== ref.current?.innerText) {
      setInnerHTML(value);
    }
  }, [value]);

  return (
    <div className={className}>
      <Content
        ref={ref}
        contentEditable={!disabled && !readOnly}
        onInput={wrappedEvent(onInput)}
        onBlur={wrappedEvent(onBlur)}
        onKeyDown={wrappedEvent(onKeyDown)}
        data-placeholder={placeholder}
        role="textbox"
        dangerouslySetInnerHTML={{
          __html: innerHTML,
        }}
        {...rest}
      />
      {children}
    </div>
  );
}

const Content = styled.span`
  &:empty {
    display: inline-block;
  }

  &:empty::before {
    display: inline-block;
    color: ${(props) => props.theme.placeholder};
    -webkit-text-fill-color: ${(props) => props.theme.placeholder};
    content: attr(data-placeholder);
    pointer-events: none;
    height: 0;
  }
`;

export default React.memo<Props>(ContentEditable);
