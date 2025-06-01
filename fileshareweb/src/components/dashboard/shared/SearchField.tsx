import { TextField, styled } from '@mui/material';

export const SearchField = styled(TextField)(({ theme }) => ({
  '& .MuiOutlinedInput-root': {
    color: '#00ff00',
    '& fieldset': {
      borderColor: 'rgba(0, 255, 0, 0.3)',
    },
    '&:hover fieldset': {
      borderColor: 'rgba(0, 255, 0, 0.5)',
    },
    '&.Mui-focused fieldset': {
      borderColor: '#00ff00',
    },
  },
  '& .MuiInputLabel-root': {
    color: 'rgba(0, 255, 0, 0.7)',
  },
}));
