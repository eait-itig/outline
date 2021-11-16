import isPrintableKeyEvent from "is-printable-key-event";
import * as React from "react";
import styled from "styled-components";

type Props = {
  disabled?: boolean;
  readOnly?: boolean;
  onChange?: (text: string) => void;
  onBlur?: (event: React.FocusEventHandler<HTMLSpanElement>) => void;
  onInput?: (event: React.FormEventHandler<HTMLSpanElement>) => void;
  onKeyDown?: (event: React.KeyboardEventHandler<HTMLSpanElement>) => void;
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
  const ref = React.useRef<HTMLSpanElement>();
  const [innerHTML, setInnerHTML] = React.useState<string>(value);
  const lastValue = React.useRef("");

  // @ts-expect-error ts-migrate(7006) FIXME: Parameter 'callback' implicitly has an 'any' type.
  const wrappedEvent = (callback) => (
    event: React.SyntheticEvent<HTMLInputElement>
  ) => {
    const text = ref.current?.innerText || "";

    // @ts-expect-error ts-migrate(2345) FIXME: Argument of type 'SyntheticEvent<HTMLInputElement,... Remove this comment to see the full error message
    if (maxLength && isPrintableKeyEvent(event) && text.length >= maxLength) {
      event.preventDefault();
      return false;
    }

    if (text !== lastValue.current) {
      lastValue.current = text;
      onChange && onChange(text);
    }

    callback && callback(event);
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
        contentEditable={!disabled && !readOnly}
        onInput={wrappedEvent(onInput)}
        onBlur={wrappedEvent(onBlur)}
        onKeyDown={wrappedEvent(onKeyDown)}
        ref={ref}
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